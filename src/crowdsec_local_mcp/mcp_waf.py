import json
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any
from collections.abc import Callable

import jsonschema
import requests
import yaml

from mcp import types

from .mcp_core import (
    LOGGER,
    PROMPTS_DIR,
    REGISTRY,
    SCRIPT_DIR,
    ToolHandler,
    docker_permission_hint,
    ensure_docker_cli,
    ensure_docker_compose_cli,
)

WAF_TOP_LEVEL_PROMPT_FILE = PROMPTS_DIR / "prompt-waf-top-level.txt"
WAF_PROMPT_FILE = PROMPTS_DIR / "prompt-waf.txt"
WAF_EXAMPLES_FILE = PROMPTS_DIR / "prompt-waf-examples.txt"
WAF_DEPLOY_FILE = PROMPTS_DIR / "prompt-waf-deploy.txt"
WAF_TESTS_PROMPT_FILE = PROMPTS_DIR / "prompt-waf-tests.txt"

CROWDSEC_SCHEMAS_DIR = SCRIPT_DIR / "yaml-schemas"
WAF_SCHEMA_FILE = CROWDSEC_SCHEMAS_DIR / "appsec_rules_schema.yaml"

WAF_TEST_COMPOSE_DIR = SCRIPT_DIR / "compose" / "waf-test"
WAF_TEST_COMPOSE_FILE = WAF_TEST_COMPOSE_DIR / "docker-compose.yml"
WAF_TEST_RULE_PATH = WAF_TEST_COMPOSE_DIR / "rules" / "current-rule.yaml"
WAF_TEST_APPSEC_TEMPLATE = (
    WAF_TEST_COMPOSE_DIR
    / "crowdsec"
    / "appsec-configs"
    / "mcp-appsec.yaml.template"
)
WAF_TEST_APPSEC_CONFIG = (
    WAF_TEST_COMPOSE_DIR
    / "crowdsec"
    / "appsec-configs"
    / "mcp-appsec.yaml"
)
WAF_RULE_NAME_PLACEHOLDER = "__PLACEHOLDER_FOR_USER_RULE__"
WAF_TEST_PROJECT_NAME = "crowdsec-mcp-waf"
WAF_TEST_NETWORK_NAME = f"{WAF_TEST_PROJECT_NAME}_waf-net"
WAF_DEFAULT_TARGET_URL = "http://nginx-appsec"
WAF_DEFAULT_NUCLEI_IMAGE = "projectdiscovery/nuclei:latest"

DEFAULT_EXPLOIT_REPOSITORIES = [
    "https://github.com/projectdiscovery/nuclei-templates.git",
]
DEFAULT_EXPLOIT_TARGET_DIR = SCRIPT_DIR / "cached-exploits"

CASE_SENSITIVE_MATCH_TYPES = ["regex", "contains", "startsWith", "endsWith", "equals"]
SQL_KEYWORD_INDICATORS = ["union", "select", "insert", "update", "delete", "drop"]

_COMPOSE_STACK_PROCESS: subprocess.Popen | None = None


def _collect_compose_logs(services: list[str] | None = None, tail_lines: int = 200) -> str:
    cmd = ensure_docker_compose_cli() + [
        "-p",
        WAF_TEST_PROJECT_NAME,
        "-f",
        str(WAF_TEST_COMPOSE_FILE),
        "logs",
    ]
    if services:
        cmd.extend(services)

    result = subprocess.run(
        cmd,
        cwd=str(WAF_TEST_COMPOSE_DIR),
        capture_output=True,
        text=True,
        check=False,
    )

    combined = "\n".join(
        part.strip()
        for part in ((result.stdout or ""), (result.stderr or ""))
        if part
    ).strip()

    if not combined:
        return ""

    lines = combined.splitlines()
    if tail_lines and len(lines) > tail_lines:
        lines = lines[-tail_lines:]
        lines.insert(0, f"(showing last {tail_lines} lines)")
    return "\n".join(lines)


def _run_compose_command(
    args: list[str], capture_output: bool = True, check: bool = True
) -> subprocess.CompletedProcess:
    """Run a docker compose command inside the WAF test harness directory."""
    base_cmd = ensure_docker_compose_cli()
    full_cmd = base_cmd + ["-p", WAF_TEST_PROJECT_NAME, "-f", str(WAF_TEST_COMPOSE_FILE)] + args
    LOGGER.info("Executing compose command: %s", " ".join(full_cmd))

    try:
        return subprocess.run(
            full_cmd,
            cwd=str(WAF_TEST_COMPOSE_DIR),
            check=check,
            capture_output=capture_output,
            text=True,
        )
    except (FileNotFoundError, PermissionError) as error:
        LOGGER.error("Compose command failed to start: %s", error)
        raise RuntimeError(
            "Docker Compose is required but could not be executed. "
            "Install Docker and ensure the current user can run `docker compose` commands."
        ) from error
    except subprocess.CalledProcessError as error:
        stdout = (error.stdout or "").strip()
        stderr = (error.stderr or "").strip()
        combined = "\n".join(part for part in (stdout, stderr) if part)
        if not combined:
            combined = str(error)
        hint = docker_permission_hint(stdout, stderr)
        LOGGER.error(
            "Compose command exited with %s: %s",
            error.returncode,
            combined.splitlines()[0] if combined else "no output",
        )
        raise RuntimeError(
            f"docker compose {' '.join(args)} failed (exit code {error.returncode}):\n{combined}{hint}"
        ) from error


def _run_compose_exec(
    args: list[str], capture_output: bool = True, check: bool = True
) -> subprocess.CompletedProcess:
    """Run docker compose exec against the CrowdSec container."""
    exec_args = ["exec", "-T"] + args
    return _run_compose_command(exec_args, capture_output=capture_output, check=check)


def _teardown_compose_stack(check: bool = True) -> None:
    """Stop the compose stack and ensure any supervising process is terminated."""
    global _COMPOSE_STACK_PROCESS
    if not WAF_TEST_COMPOSE_FILE.exists():
        LOGGER.warning(
            "Requested stack teardown but compose file %s is missing", WAF_TEST_COMPOSE_FILE
        )
        _COMPOSE_STACK_PROCESS = None
        return

    LOGGER.info("Stopping WAF test stack")
    try:
        _run_compose_command(["down"], check=check)
    finally:
        if _COMPOSE_STACK_PROCESS is not None:
            try:
                _COMPOSE_STACK_PROCESS.wait(timeout=15)
            except subprocess.TimeoutExpired:
                LOGGER.warning(
                    "Compose stack process did not exit in time; terminating forcefully"
                )
                _COMPOSE_STACK_PROCESS.kill()
                _COMPOSE_STACK_PROCESS.wait(timeout=5)
        _COMPOSE_STACK_PROCESS = None


def _wait_for_crowdsec_ready(timeout: int = 90) -> None:
    """Wait until the CrowdSec local API is reachable."""
    global _COMPOSE_STACK_PROCESS
    LOGGER.info("Waiting for CrowdSec API to become ready (timeout=%s)", timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _COMPOSE_STACK_PROCESS is not None:
            exit_code = _COMPOSE_STACK_PROCESS.poll()
            if exit_code is not None:
                _COMPOSE_STACK_PROCESS = None
                logs = _collect_compose_logs(["crowdsec", "nginx", "backend"])
                log_section = f"\n\nService logs:\n{logs}" if logs else ""
                raise RuntimeError(
                    "WAF stack exited while waiting for CrowdSec to become ready"
                    f" (exit code {exit_code}).{log_section}"
                )
        try:
            result = _run_compose_exec(
                ["crowdsec", "cscli", "lapi", "status"], capture_output=True, check=False
            )
            if isinstance(result, subprocess.CompletedProcess) and result.returncode == 0:
                LOGGER.info("CrowdSec API is ready")
                return
        except RuntimeError:
            pass
        time.sleep(3)

    LOGGER.error("CrowdSec API did not become ready before timeout")
    raise RuntimeError("CrowdSec local API did not become ready in time")


def _run_nuclei_container(
    workspace: Path,
    template_path: Path,
    *,
    nuclei_image: str,
    target_url: str,
    nuclei_args: list[str] | None = None,
    timeout: int = 180,
) -> tuple[bool, str]:
    """Run the provided nuclei template inside a disposable docker container."""
    rel_template = template_path.relative_to(workspace)
    container_template_path = f"/nuclei/{rel_template.as_posix()}"

    ensure_docker_cli()

    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        WAF_TEST_NETWORK_NAME,
        "-v",
        f"{workspace}:/nuclei",
        nuclei_image,
        "-t",
        container_template_path,
        "-u",
        target_url,
        "-jsonl",
        "-silent",
    ]
    if nuclei_args:
        command.extend(str(arg) for arg in nuclei_args)

    LOGGER.info("Executing nuclei container: %s", " ".join(command))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        LOGGER.error("Nuclei container timed out after %s seconds", timeout)
        return (
            False,
            "Nuclei execution timed out. Consider simplifying the template or increasing the timeout.",
        )

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    details: list[str] = []
    if stdout:
        details.append(f"stdout:\n{stdout}")
    if stderr:
        details.append(f"stderr:\n{stderr}")
    detail_text = "\n\n".join(details)

    if result.returncode != 0:
        LOGGER.error("Nuclei container exited with code %s", result.returncode)
        hint = docker_permission_hint(stdout, stderr)
        failure = (
            f"Nuclei container exited with status {result.returncode}."
            + (f"\n\n{detail_text}" if detail_text else "")
            + hint
        )
        return (False, failure)

    matches: list[dict[str, Any]] = []
    unmatched_lines: list[str] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            if isinstance(payload, dict):
                matches.append(payload)
            else:
                unmatched_lines.append(line)
        except json.JSONDecodeError:
            unmatched_lines.append(line)

    if not matches:
        LOGGER.warning("Nuclei execution completed but no matches were reported")
        info_lines = []
        if unmatched_lines:
            info_lines.append("Nuclei produced output but no matches were recorded:\n" + "\n".join(unmatched_lines))
        else:
            info_lines.append(
                "Nuclei completed successfully but reported zero matches. "
                "The WAF rule likely did not block the request (missing HTTP 403)."
            )
        if stderr:
            info_lines.append(f"stderr:\n{stderr}")
        return (False, "\n\n".join(info_lines))

    summary_lines = [
        f"Nuclei reported {len(matches)} match(es) using template {rel_template.name}.",
    ]
    for match in matches:
        template_id = match.get("template-id") or match.get("templateID") or rel_template.stem
        url = match.get("matched-at") or match.get("matchedAt") or target_url
        summary_lines.append(f" - {template_id} matched at {url}")
    if unmatched_lines:
        summary_lines.append(
            "Additional nuclei output:\n" + "\n".join(unmatched_lines)
        )
    if stderr:
        summary_lines.append(f"stderr:\n{stderr}")
    return (True, "\n".join(summary_lines))


def _start_waf_test_stack(rule_yaml: str) -> tuple[str | None, str | None]:
    global _COMPOSE_STACK_PROCESS
    LOGGER.info("Starting WAF test stack")
    if not WAF_TEST_COMPOSE_FILE.exists():
        LOGGER.error("Compose file missing at %s", WAF_TEST_COMPOSE_FILE)
        return (
            None,
            "Docker compose stack not found; expected compose/waf-test/docker-compose.yml",
        )

    try:
        rule_metadata = yaml.safe_load(rule_yaml) or {}
    except yaml.YAMLError as exc:
        LOGGER.error("Failed to parse WAF rule YAML: %s", exc)
        return (None, f"Cannot parse WAF rule YAML: {exc}")

    if not isinstance(rule_metadata, dict):
        return (None, "WAF rule YAML must define a top-level mapping")

    rule_name = rule_metadata.get("name")
    if not isinstance(rule_name, str) or not rule_name.strip():
        LOGGER.warning("WAF rule YAML missing required 'name' field")
        return (None, "WAF rule YAML must include a non-empty string 'name' field")
    rule_name = rule_name.strip()

    if not WAF_TEST_APPSEC_TEMPLATE.exists():
        LOGGER.error("AppSec template missing at %s", WAF_TEST_APPSEC_TEMPLATE)
        return (
            None,
            "AppSec config template not found; expected compose/waf-test/crowdsec/appsec-configs/mcp-appsec.yaml.template",
        )

    template_content = WAF_TEST_APPSEC_TEMPLATE.read_text(encoding="utf-8")
    if WAF_RULE_NAME_PLACEHOLDER not in template_content:
        return (None, "AppSec config template missing rule name placeholder")

    rendered_appsec_config = template_content.replace(WAF_RULE_NAME_PLACEHOLDER, rule_name)

    WAF_TEST_COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    WAF_TEST_RULE_PATH.parent.mkdir(parents=True, exist_ok=True)
    WAF_TEST_RULE_PATH.write_text(rule_yaml, encoding="utf-8")
    WAF_TEST_APPSEC_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    WAF_TEST_APPSEC_CONFIG.write_text(rendered_appsec_config, encoding="utf-8")

    if _COMPOSE_STACK_PROCESS is not None:
        if _COMPOSE_STACK_PROCESS.poll() is None:
            LOGGER.warning("Stack start requested while previous stack still running")
            return (
                None,
                "WAF test stack appears to be running already. Stop it before starting a new session.",
            )
        _COMPOSE_STACK_PROCESS = None

    try:
        _run_compose_command(["up", "-d", "crowdsec"])
    except RuntimeError as error:
        LOGGER.error("Failed to start CrowdSec container: %s", error)
        logs = _collect_compose_logs(["crowdsec"])
        message = str(error)
        if logs:
            message = f"{message}\n\nCrowdSec logs:\n{logs}"
        return (None, message)

    try:
        _wait_for_crowdsec_ready()
    except RuntimeError as error:
        LOGGER.error("CrowdSec failed readiness check: %s", error)
        logs = _collect_compose_logs(["crowdsec"])
        log_section = f"\n\nCrowdSec logs:\n{logs}" if logs else ""
        _teardown_compose_stack(check=False)
        return (None, f"{error}{log_section}")

    compose_base = ensure_docker_compose_cli() + [
        "-p",
        WAF_TEST_PROJECT_NAME,
        "-f",
        str(WAF_TEST_COMPOSE_FILE),
        "up",
        "--build",
        "--abort-on-container-exit",
    ]

    try:
        process = subprocess.Popen(
            compose_base + ["crowdsec", "nginx", "backend"],
            cwd=str(WAF_TEST_COMPOSE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    except (FileNotFoundError, PermissionError):
        LOGGER.error("Failed to launch docker compose process")
        return (
            None,
            "Docker Compose is required but could not be executed. Ensure Docker is installed and the current user can run Docker commands.",
        )

    _COMPOSE_STACK_PROCESS = process

    time.sleep(2)
    immediate_exit = process.poll()
    if immediate_exit is not None:
        LOGGER.error("Compose process exited immediately with code %s", immediate_exit)
        logs = _collect_compose_logs(["crowdsec", "nginx", "backend"])
        log_section = f"\n\nService logs:\n{logs}" if logs else ""
        _teardown_compose_stack(check=False)
        return (
            None,
            f"docker compose up failed to start the stack (exit code {immediate_exit}).{log_section}",
        )

    LOGGER.info("WAF test stack started successfully")
    return ("http://localhost:8081", None)


def _stop_waf_test_stack() -> None:
    LOGGER.info("Stopping WAF test stack via tool request")
    _teardown_compose_stack(check=True)


def _validate_waf_rule(rule_yaml: str) -> list[types.TextContent]:
    """Validate that a CrowdSec WAF rule YAML conforms to the schema."""
    LOGGER.info("Validating WAF rule YAML (size=%s bytes)", len(rule_yaml.encode("utf-8")))
    if not WAF_SCHEMA_FILE.exists():
        LOGGER.error("Schema file missing at %s", WAF_SCHEMA_FILE)
        raise FileNotFoundError(f"Schema file {WAF_SCHEMA_FILE} not found")

    try:
        schema = yaml.safe_load(WAF_SCHEMA_FILE.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        LOGGER.error("Failed to parse WAF schema YAML: %s", exc)
        raise ValueError(f"Unable to parse WAF schema YAML: {exc!s}") from exc

    try:
        parsed = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as exc:
        LOGGER.error("YAML syntax error during validation: %s", exc)
        raise ValueError(f"YAML syntax error: {exc!s}") from exc

    if parsed is None:
        LOGGER.warning("Validation request received empty YAML content")
        raise ValueError("Empty or invalid YAML content")

    if not isinstance(parsed, dict):
        raise ValueError("YAML must be a dictionary/object")

    try:
        jsonschema.validate(instance=parsed, schema=schema)
    except jsonschema.ValidationError as exc:
        error_path = " -> ".join(str(p) for p in exc.absolute_path) if exc.absolute_path else "root"
        LOGGER.warning("Schema validation error at %s: %s", error_path, exc.message)
        raise ValueError(f"Schema validation error at {error_path}: {exc.message}") from exc
    except jsonschema.SchemaError as exc:
        LOGGER.error("Invalid schema encountered: %s", exc)
        raise RuntimeError(f"Invalid schema: {exc!s}") from exc

    LOGGER.info("WAF rule validation passed")
    return [
        types.TextContent(
            type="text",
            text="✅ VALIDATION PASSED: Rule conforms to CrowdSec AppSec schema",
        )
    ]


def _analyze_rule_item(
    rule_item: Any, rule_path: str, warnings: list[str]
) -> tuple[bool, bool]:
    """Recursively inspect rule items, track operator usage, and record warnings."""
    if not isinstance(rule_item, dict):
        return (False, False)

    location = f"rules{rule_path}" if rule_path else "rules"
    has_and = "and" in rule_item
    has_or = "or" in rule_item
    contains_and = has_and
    contains_or = has_or

    if has_and and has_or:
        warnings.append(
            f"{location} mixes 'and' and 'or' operators at the same level; split them into separate nested blocks"
        )

    if has_and:
        for i, sub_rule in enumerate(rule_item["and"]):
            child_and, child_or = _analyze_rule_item(
                sub_rule,
                f"{rule_path}.and[{i}]",
                warnings,
            )
            contains_and = contains_and or child_and
            contains_or = contains_or or child_or

    if has_or:
        for i, sub_rule in enumerate(rule_item["or"]):
            child_and, child_or = _analyze_rule_item(
                sub_rule,
                f"{rule_path}.or[{i}]",
                warnings,
            )
            contains_and = contains_and or child_and
            contains_or = contains_or or child_or

    if "match" in rule_item and not (has_and or has_or):
        match = rule_item["match"]
        if isinstance(match, dict):
            match_type = match.get("type", "")
            match_value = match.get("value", "")

            if (
                match_type in CASE_SENSITIVE_MATCH_TYPES
                and isinstance(match_value, str)
                and any(c.isupper() for c in match_value)
            ):
                transforms = rule_item.get("transform", [])
                has_lowercase = (
                    "lowercase" in transforms if isinstance(transforms, list) else False
                )

                if not has_lowercase:
                    warnings.append(
                        f"Match at {location} uses '{match_type}' with uppercase letters "
                        f"but no 'lowercase' transform - consider adding lowercase transform for case-insensitive matching"
                    )

            if isinstance(match_value, str):
                lower_value = match_value.lower()
                sql_keywords = [kw for kw in SQL_KEYWORD_INDICATORS if kw in lower_value]
                if sql_keywords:
                    keywords_str = ", ".join(sorted(set(sql_keywords)))
                    warnings.append(
                        f"Match at {location} contains SQL keyword(s) ({keywords_str}); instead of keyword blacklisting, detect escaping characters like quotes or semicolons"
                    )

                transforms = rule_item.get("transform", [])
                if isinstance(transforms, list) and "urldecode" in transforms:
                    if "%" in match_value:
                        warnings.append(
                            f"Match at {location} applies 'urldecode' but still contains percent-encoded characters; ensure the value is properly decoded or add another urldecode pass."
                        )

    return (contains_and, contains_or)


def lint_waf_rule(rule_yaml: str) -> list[types.TextContent]:
    """Lint a CrowdSec WAF rule and provide warnings/hints for improvement."""
    LOGGER.info("Linting WAF rule YAML (size=%s bytes)", len(rule_yaml.encode("utf-8")))
    try:
        parsed = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as exc:
        LOGGER.error("Lint failed due to YAML error: %s", exc)
        raise ValueError(f"Cannot lint invalid YAML: {exc!s}") from exc

    if parsed is None:
        LOGGER.warning("Lint request failed: YAML content was empty or invalid")
        raise ValueError("Cannot lint empty or invalid YAML")

    warnings: list[str] = []
    hints: list[str] = []

    if not isinstance(parsed, dict):
        warnings.append("Rule should be a YAML dictionary")

    if "name" not in parsed:
        warnings.append("Missing 'name' field")

    if "rules" not in parsed:
        warnings.append("Missing 'rules' field")

    if "labels" not in parsed:
        warnings.append("Missing 'labels' field")

    if "name" in parsed:
        name = parsed.get("name", "")
        if isinstance(name, str):
            if name.startswith("crowdsecurity/"):
                warnings.append(
                    "Rule name starts with 'crowdsecurity/' which is reserved for official CrowdSec rules; consider using your own namespace"
                )
        else:
            warnings.append("Field 'name' should be a string")

    if "rules" in parsed and isinstance(parsed["rules"], list):
        for i, rule in enumerate(parsed["rules"]):
            rule_has_and, rule_has_or = _analyze_rule_item(rule, f"[{i}]", warnings)
            if rule_has_and and rule_has_or:
                warnings.append(
                    f"rules[{i}] uses both 'and' and 'or' operators somewhere in the block; CrowdSec cannot mix them in one rule, split the logic into separate rules"
                )

    result_lines: list[str] = []

    if not warnings and not hints:
        result_lines.append("✅ LINT PASSED: No issues found")
        LOGGER.info("Lint completed with no findings")
    else:
        if warnings:
            result_lines.append("⚠️  WARNINGS:")
            for warning in warnings:
                result_lines.append(f"  - {warning}")
            LOGGER.warning("Lint completed with %s warning(s)", len(warnings))

        if hints:
            if warnings:
                result_lines.append("")
            result_lines.append("💡 HINTS:")
            for hint in hints:
                result_lines.append(f"  - {hint}")
            LOGGER.info("Lint completed with %s hint(s)", len(hints))

    return [
        types.TextContent(
            type="text",
            text="\n".join(result_lines),
        )
    ]


def _tool_get_waf_top_level_prompt(_: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        LOGGER.info("Serving WAF top-level orchestration prompt content")
        prompt_content = WAF_TOP_LEVEL_PROMPT_FILE.read_text(encoding="utf-8")
        return [
            types.TextContent(
                type="text",
                text=prompt_content,
            )
        ]
    except FileNotFoundError as exc:
        LOGGER.error("WAF top-level prompt file not found at %s", WAF_TOP_LEVEL_PROMPT_FILE)
        raise FileNotFoundError(
            f"WAF top-level prompt file not found at {WAF_TOP_LEVEL_PROMPT_FILE}"
        ) from exc
    except Exception as exc:
        LOGGER.error("Error loading WAF top-level prompt: %s", exc)
        raise RuntimeError(f"Error reading WAF top-level prompt file: {exc!s}") from exc


def _tool_get_waf_prompt(_: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        LOGGER.info("Serving WAF prompt content")
        prompt_content = WAF_PROMPT_FILE.read_text(encoding="utf-8")
        return [
            types.TextContent(
                type="text",
                text=prompt_content,
            )
        ]
    except FileNotFoundError as exc:
        LOGGER.error("WAF prompt file not found at %s", WAF_PROMPT_FILE)
        raise FileNotFoundError(f"WAF prompt file not found at {WAF_PROMPT_FILE}") from exc
    except Exception as exc:
        LOGGER.error("Error loading WAF prompt: %s", exc)
        raise RuntimeError(f"Error reading WAF prompt file: {exc!s}") from exc


def _tool_get_waf_examples(_: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        LOGGER.info("Serving WAF examples content")
        examples_content = WAF_EXAMPLES_FILE.read_text(encoding="utf-8")
        return [
            types.TextContent(
                type="text",
                text=examples_content,
            )
        ]
    except FileNotFoundError as exc:
        LOGGER.error("WAF examples file not found at %s", WAF_EXAMPLES_FILE)
        raise FileNotFoundError(f"WAF examples file not found at {WAF_EXAMPLES_FILE}") from exc
    except Exception as exc:
        LOGGER.error("Error loading WAF examples: %s", exc)
        raise RuntimeError(f"Error reading WAF examples file: {exc!s}") from exc


def _tool_generate_waf_rule(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        main_prompt = WAF_PROMPT_FILE.read_text(encoding="utf-8")
        examples_prompt = WAF_EXAMPLES_FILE.read_text(encoding="utf-8")

        combined_prompt = f"{main_prompt}\n\n{examples_prompt}"

        nuclei_template = arguments.get("nuclei_template") if arguments else None
        LOGGER.info(
            "Generating WAF rule prompt (nuclei_template_present=%s)",
            bool(nuclei_template),
        )
        if nuclei_template:
            combined_prompt += (
                "\n\n### Input Nuclei Template to Process:\n"
                f"```yaml\n{nuclei_template}\n```"
            )

        return [
            types.TextContent(
                type="text",
                text=combined_prompt,
            )
        ]
    except FileNotFoundError as exc:
        LOGGER.error("Prompt generation failed due to missing file: %s", exc)
        raise FileNotFoundError(f"Prompt file not found: {exc!s}") from exc
    except Exception as exc:
        LOGGER.error("Unexpected error generating WAF prompt: %s", exc)
        raise RuntimeError(f"Error generating WAF rule prompt: {exc!s}") from exc


def _tool_generate_waf_tests(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        tests_prompt = WAF_TESTS_PROMPT_FILE.read_text(encoding="utf-8")
        nuclei_template = arguments.get("nuclei_template") if arguments else None
        rule_filename = arguments.get("rule_filename") if arguments else None

        LOGGER.info(
            "Generating WAF test prompt (nuclei_template_present=%s, rule_filename_present=%s)",
            bool(nuclei_template),
            bool(rule_filename),
        )

        combined_prompt = tests_prompt

        if rule_filename:
            combined_prompt += (
                "\n\n### Rule Under Test\n"
                f"The detection rule produced earlier is stored at: {rule_filename}\n"
                "Use this exact path in the config.yaml `appsec-rules` list."
            )

        if nuclei_template:
            combined_prompt += (
                "\n\n### Input Nuclei Template to Adapt:\n"
                f"```yaml\n{nuclei_template}\n```"
            )

        return [
            types.TextContent(
                type="text",
                text=combined_prompt,
            )
        ]
    except FileNotFoundError as exc:
        LOGGER.error("WAF test prompt missing: %s", exc)
        raise FileNotFoundError(f"WAF test prompt file not found: {exc!s}") from exc
    except Exception as exc:
        LOGGER.error("Unexpected error generating WAF test prompt: %s", exc)
        raise RuntimeError(f"Error generating WAF test prompt: {exc!s}") from exc


def _tool_validate_waf_rule(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    if not arguments or "rule_yaml" not in arguments:
        LOGGER.warning("Validation request missing 'rule_yaml' argument")
        raise ValueError("rule_yaml parameter is required")

    rule_yaml = arguments["rule_yaml"]
    if not isinstance(rule_yaml, str):
        raise TypeError("rule_yaml must be provided as a string")

    LOGGER.info("Received validation request for WAF rule")
    return _validate_waf_rule(rule_yaml)


def _tool_lint_waf_rule(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    if not arguments or "rule_yaml" not in arguments:
        LOGGER.warning("Lint request missing 'rule_yaml' argument")
        raise ValueError("rule_yaml parameter is required")

    rule_yaml = arguments["rule_yaml"]
    if not isinstance(rule_yaml, str):
        raise TypeError("rule_yaml must be provided as a string")

    LOGGER.info("Received lint request for WAF rule")
    return lint_waf_rule(rule_yaml)


def _tool_deploy_waf_rule(_: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        LOGGER.info("Serving WAF deployment guide content")
        deploy_content = WAF_DEPLOY_FILE.read_text(encoding="utf-8")
        return [
            types.TextContent(
                type="text",
                text=deploy_content,
            )
        ]
    except FileNotFoundError as exc:
        LOGGER.error("WAF deployment guide missing at %s", WAF_DEPLOY_FILE)
        raise FileNotFoundError(f"WAF deployment guide file not found at {WAF_DEPLOY_FILE}") from exc
    except Exception as exc:
        LOGGER.error("Error loading WAF deployment guide: %s", exc)
        raise RuntimeError(f"Error reading WAF deployment guide: {exc!s}") from exc


def _tool_manage_waf_stack(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        if not arguments:
            LOGGER.warning("manage_waf_stack called without arguments")
            raise ValueError("Missing arguments payload")

        action = arguments.get("action")
        if action not in {"start", "stop"}:
            LOGGER.warning("manage_waf_stack received invalid action: %s", action)
            raise ValueError("Action must be 'start' or 'stop'")

        if action == "start":
            rule_yaml = arguments.get("rule_yaml")
            if not isinstance(rule_yaml, str) or not rule_yaml.strip():
                LOGGER.warning("manage_waf_stack start called without rule YAML")
                raise ValueError("'rule_yaml' must be provided when starting the stack")

            LOGGER.info("manage_waf_stack starting WAF stack")
            target_url, error_message = _start_waf_test_stack(rule_yaml)
            if error_message:
                LOGGER.error("Failed to start WAF stack: %s", error_message)
                raise RuntimeError(f"WAF stack start error: {error_message}")

            if not target_url:
                LOGGER.error("WAF stack start returned no target URL and no explicit error")
                raise RuntimeError(
                    "WAF stack start error: stack did not return a service URL and reported no specific error."
                )

            return [
                types.TextContent(
                    type="text",
                    text=(
                        "✅ WAF test stack is up. The nginx entry-point is available at "
                        f"{target_url}. Issue malicious payloads that should be blocked as well as "
                        "benign requests that must remain allowed, then use 'manage_waf_stack' with "
                        "action=stop when finished."
                    ),
                )
            ]

        LOGGER.info("manage_waf_stack stopping WAF stack")
        _stop_waf_test_stack()
        return [
            types.TextContent(
                type="text",
                text="🛑 WAF test stack stopped and containers removed",
            )
        ]

    except Exception as exc:
        LOGGER.error("manage_waf_stack error: %s", exc, exc_info=True)
        raise


def _tool_run_waf_tests(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    stack_started_here = False
    try:
        if not arguments:
            LOGGER.warning("run_waf_tests called without arguments")
            raise ValueError("Missing arguments payload")

        rule_yaml = arguments.get("rule_yaml")
        nuclei_yaml = arguments.get("nuclei_yaml")

        if not isinstance(rule_yaml, str) or not rule_yaml.strip():
            raise ValueError("'rule_yaml' must be a non-empty string")
        if not isinstance(nuclei_yaml, str) or not nuclei_yaml.strip():
            raise ValueError("'nuclei_yaml' must be a non-empty string")

        LOGGER.info(
            "Starting WAF stack for nuclei test (image=%s, target_url=%s)",
            WAF_DEFAULT_NUCLEI_IMAGE,
            WAF_DEFAULT_TARGET_URL,
        )

        target_endpoint, stack_error = _start_waf_test_stack(rule_yaml)
        if stack_error:
            if "appears to be running already" in stack_error.lower():
                LOGGER.info("Existing stack detected; attempting restart before running tests")
                _stop_waf_test_stack()
                target_endpoint, stack_error = _start_waf_test_stack(rule_yaml)
            if stack_error:
                LOGGER.error("Unable to start WAF stack: %s", stack_error)
                raise RuntimeError(f"Unable to start WAF stack: {stack_error}")
        stack_started_here = True

        with tempfile.TemporaryDirectory(prefix="waf-test-") as temp_dir:
            workspace = Path(temp_dir)

            template_path = workspace / "nuclei-template.yaml"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(nuclei_yaml, encoding="utf-8")

            LOGGER.info(
                "Running nuclei template against %s (image=%s)",
                WAF_DEFAULT_TARGET_URL,
                WAF_DEFAULT_NUCLEI_IMAGE,
            )
            success, message = _run_nuclei_container(
                workspace,
                template_path,
                nuclei_image=WAF_DEFAULT_NUCLEI_IMAGE,
                target_url=WAF_DEFAULT_TARGET_URL,
            )

        if not success:
            stack_logs = _collect_compose_logs(["crowdsec", "nginx"])
            parts = [
                "❌ Nuclei test failed.",
                "=== NUCLEI OUTPUT ===",
                message,
            ]
            if stack_logs:
                parts.append("=== STACK LOGS (crowdsec/nginx) ===")
                parts.append(stack_logs)
            joined = "\n\n".join(parts)
            raise RuntimeError(joined)

        success_sections = [
            "✅ Nuclei test succeeded.",
            f"Target endpoint inside the stack: {WAF_DEFAULT_TARGET_URL}",
            f"Host accessible endpoint: {target_endpoint or 'unknown'}",
            "=== NUCLEI OUTPUT ===",
            message,
        ]
        stack_logs = _collect_compose_logs(["crowdsec", "nginx"])
        if stack_logs:
            success_sections.extend(
                [
                    "=== STACK LOGS (crowdsec/nginx) ===",
                    stack_logs,
                ]
            )
        return [
            types.TextContent(
                type="text",
                text="\n\n".join(success_sections),
            )
        ]

    except Exception as exc:
        LOGGER.error("run_waf_tests error: %s", exc, exc_info=True)
        raise
    finally:
        if stack_started_here:
            try:
                _stop_waf_test_stack()
            except Exception as stop_exc:  # pragma: no cover - best effort cleanup
                LOGGER.warning("Failed to stop WAF stack during cleanup: %s", stop_exc)

def _search_repo_for_cve(repo_path: Path, cve: str) -> list[Path]:
    """Return files whose name contains the CVE identifier (case-insensitive)."""
    lower_token = cve.lower()
    matches: list[Path] = []

    for candidate in repo_path.rglob("*"):
        if not candidate.is_file():
            continue
        if lower_token in candidate.name.lower():
            matches.append(candidate)

    return matches


def _tool_fetch_nuclei_exploit(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        if not arguments:
            LOGGER.warning("fetch_nuclei_exploit called without arguments")
            raise ValueError("Missing arguments payload")

        raw_cve = arguments.get("cve")
        if not isinstance(raw_cve, str) or not raw_cve.strip():
            LOGGER.warning("fetch_nuclei_exploit received invalid CVE argument: %s", raw_cve)
            raise ValueError("cve must be a non-empty string")

        cve = raw_cve.strip().upper()
        if not cve.startswith("CVE-"):
            cve = f"CVE-{cve}"

        target_path = DEFAULT_EXPLOIT_TARGET_DIR
        target_path.mkdir(parents=True, exist_ok=True)

        LOGGER.info("Fetching nuclei exploit templates for %s", cve)
        findings: list[str] = []
        rendered_templates: list[str] = []
        total_files = 0

        for repo_url in DEFAULT_EXPLOIT_REPOSITORIES:
            cleaned_url = repo_url.rstrip("/")
            repo_name = cleaned_url.split("/")[-1] or "repository"
            if repo_name.endswith(".git"):
                repo_name = repo_name.removesuffix(".git")
            repo_path = target_path / repo_name

            if repo_path.exists():
                if not (repo_path / ".git").exists():
                    raise RuntimeError(
                        f"Destination {repo_path} exists but is not a git repository"
                    )
                git_cmd = ["git", "-C", str(repo_path), "pull", "--ff-only"]
            else:
                git_cmd = ["git", "clone", "--depth", "1", cleaned_url, str(repo_path)]

            git_result = subprocess.run(
                git_cmd,
                capture_output=True,
                text=True,
            )
            if git_result.returncode != 0:
                detail = (git_result.stderr or git_result.stdout or "git command failed").strip()
                LOGGER.error("Git operation failed for %s: %s", cleaned_url, detail)
                raise RuntimeError(f"git operation failed for {cleaned_url}: {detail}")

            matched_files = _search_repo_for_cve(repo_path, cve)
            if not matched_files:
                continue

            findings.append(f"Repository: {cleaned_url}")
            for file_path in matched_files:
                try:
                    relative_path = file_path.relative_to(repo_path)
                except ValueError:
                    relative_path = file_path
                findings.append(f"  {relative_path}")
                try:
                    try:
                        file_contents = file_path.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        file_contents = file_path.read_text(encoding="utf-8", errors="replace")
                except OSError as read_err:
                    findings.append(f"    (failed to read {relative_path}: {read_err})")
                    continue
                rendered_templates.append(
                    f"### {cleaned_url} :: {relative_path}\n```yaml\n{file_contents}\n```"
                )
                total_files += 1

        if total_files == 0:
            LOGGER.warning("No nuclei exploit templates found for %s", cve)
            detail_section = "\n\nScan details:\n" + "\n".join(findings) if findings else ""
            return [
                types.TextContent(
                    type="text",
                    text=(
                        f"No files containing {cve} were found in the provided repositories."
                        f"{detail_section}"
                    ),
                )
            ]

        summary_lines = [
            f"Fetched {total_files} template(s) containing {cve} from configured repositories.",
            "\n".join(findings),
            "",
            "Present each template below to the user inside a ```yaml``` code block:",
            "",
            "\n\n".join(rendered_templates),
        ]

        return [
            types.TextContent(
                type="text",
                text="\n".join(summary_lines),
            )
        ]

    except Exception as exc:
        LOGGER.error("fetch_nuclei_exploit error: %s", exc, exc_info=True)
        raise


def _tool_curl_waf_endpoint(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        if not arguments:
            LOGGER.warning("curl_waf_endpoint called without arguments")
            raise ValueError("Missing arguments payload")

        method = arguments.get("method")
        path = arguments.get("path")
        body = arguments.get("body")
        headers = arguments.get("headers") or {}
        timeout = arguments.get("timeout", 10)

        if not isinstance(method, str) or not isinstance(path, str):
            LOGGER.warning("curl_waf_endpoint received invalid method/path types")
            raise ValueError("'method' and 'path' must be strings")

        method = method.upper().strip()
        path = path.strip() or "/"

        if not path.startswith("/"):
            if "://" in path:
                parsed = urllib.parse.urlparse(path)
                path = urllib.parse.urlunparse(
                    ("", "", parsed.path or "/", parsed.params, parsed.query, parsed.fragment)
                )
            else:
                path = "/" + path

        if body is not None and not isinstance(body, str):
            LOGGER.warning("curl_waf_endpoint received non-string body payload")
            raise ValueError("'body' must be a string when provided")

        LOGGER.info(
            "curl_waf_endpoint executing %s request to %s (timeout=%s)", method, path, timeout
        )
        try:
            response = requests.request(
                method=method,
                url=f"http://localhost:8081{path}",
                headers=headers if isinstance(headers, dict) else {},
                data=body,
                timeout=timeout,
            )
        except requests.RequestException as req_err:
            raise RuntimeError(f"HTTP request failed: {req_err}") from req_err

        header_lines = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        response_text = (
            f">>> {method} http://localhost:8081{path}\n"
            f"Status: {response.status_code}\n"
            f"Headers:\n{header_lines}\n\n"
            f"Body:\n{response.text}"
        )

        LOGGER.info(
            "curl_waf_endpoint completed with status %s for %s %s",
            response.status_code,
            method,
            path,
        )
        return [
            types.TextContent(
                type="text",
                text=response_text,
            )
        ]

    except Exception as exc:
        LOGGER.error("curl_waf_endpoint error: %s", exc, exc_info=True)
        raise


WAF_TOOL_HANDLERS: dict[str, ToolHandler] = {
    "get_waf_top_level_prompt": _tool_get_waf_top_level_prompt,
    "get_waf_prompt": _tool_get_waf_prompt,
    "get_waf_examples": _tool_get_waf_examples,
    "generate_waf_rule": _tool_generate_waf_rule,
    "generate_waf_tests": _tool_generate_waf_tests,
    "validate_waf_rule": _tool_validate_waf_rule,
    "lint_waf_rule": _tool_lint_waf_rule,
    "deploy_waf_rule": _tool_deploy_waf_rule,
    "fetch_nuclei_exploit": _tool_fetch_nuclei_exploit,
    "manage_waf_stack": _tool_manage_waf_stack,
    "run_waf_tests": _tool_run_waf_tests,
    "curl_waf_endpoint": _tool_curl_waf_endpoint,
}

WAF_TOOLS: list[types.Tool] = [
    types.Tool(
        name="get_waf_top_level_prompt",
        description="Get the top-level CrowdSec WAF workflow prompt that explains how to approach rule and test creation",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_waf_prompt",
        description="Get the main WAF rule generation prompt for CrowdSec",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_waf_examples",
        description="Get WAF rule generation examples for CrowdSec",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="generate_waf_rule",
        description="Get the complete WAF rule generation prompt (main prompt + examples) for CrowdSec",
        inputSchema={
            "type": "object",
            "properties": {
                "nuclei_template": {
                    "type": "string",
                    "description": "Optional Nuclei template to include in the prompt for immediate processing",
                }
            },
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="generate_waf_tests",
        description="Get the WAF test generation prompt for producing config.yaml and adapted Nuclei templates",
        inputSchema={
            "type": "object",
            "properties": {
                "nuclei_template": {
                    "type": "string",
                    "description": "Optional Nuclei template to include so the assistant can adapt it for testing",
                },
                "rule_filename": {
                    "type": "string",
                    "description": "Optional path to the generated rule (e.g. ./appsec-rules/crowdsecurity/vpatch-CVE-XXXX-YYYY.yaml)",
                },
            },
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="run_waf_tests",
        description="Start the WAF harness and execute the provided nuclei test template against it",
        inputSchema={
            "type": "object",
            "properties": {
                "rule_yaml": {
                    "type": "string",
                    "description": "CrowdSec WAF rule YAML to load into the harness before running tests",
                },
                "nuclei_yaml": {
                    "type": "string",
                    "description": "Adapted nuclei template YAML that should trigger a block (HTTP 403)",
                },
            },
            "required": ["rule_yaml", "nuclei_yaml"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="validate_waf_rule",
        description="Validate that a CrowdSec WAF rule YAML is syntactically correct",
        inputSchema={
            "type": "object",
            "properties": {
                "rule_yaml": {
                    "type": "string",
                    "description": "The YAML content of the WAF rule to validate",
                }
            },
            "required": ["rule_yaml"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="lint_waf_rule",
        description="Lint a CrowdSec WAF rule and provide warnings/hints for improvement",
        inputSchema={
            "type": "object",
            "properties": {
                "rule_yaml": {
                    "type": "string",
                    "description": "The YAML content of the WAF rule to lint",
                }
            },
            "required": ["rule_yaml"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="deploy_waf_rule",
        description="Get deployment instructions for CrowdSec WAF rules",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="fetch_nuclei_exploit",
        description="Retrieve nuclei templates from the official repository for a CVE to help with generation of WAF rules",
        inputSchema={
            "type": "object",
            "properties": {
                "cve": {
                    "type": "string",
                    "description": "CVE identifier to search for (e.g. CVE-2024-12345)",
                },
            },
            "required": ["cve"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="manage_waf_stack",
        description="Start or stop the Docker-based CrowdSec AppSec test stack so the rule can be exercised with allowed and blocked requests",
        inputSchema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["start", "stop"],
                    "description": "Whether to start or stop the stack",
                },
                "rule_yaml": {
                    "type": "string",
                    "description": "WAF rule YAML content to mount into the stack when starting",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="curl_waf_endpoint",
        description="Execute an HTTP request against the local WAF test endpoint (http://localhost:8081)",
        inputSchema={
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                    "description": "HTTP method to use",
                },
                "path": {
                    "type": "string",
                    "description": "Request path (e.g. /, /admin?x=y). Automatically prefixed with http://localhost:8081",
                },
                "body": {
                    "type": "string",
                    "description": "Optional request body",
                },
                "headers": {
                    "type": "object",
                    "description": "Optional headers to include",
                    "additionalProperties": {"type": "string"},
                },
                "timeout": {
                    "type": "number",
                    "description": "Optional curl timeout in seconds",
                    "minimum": 0.1,
                },
            },
            "required": ["method", "path"],
            "additionalProperties": False,
        },
    ),
]

WAF_RESOURCES: list[types.Resource] = [
    types.Resource(
        uri="file://prompts/prompt-waf-top-level.txt",
        name="WAF Top-Level Workflow Prompt",
        description="High-level guidance for handling CrowdSec WAF rule requests and which tools to use",
        mimeType="text/plain",
    ),
    types.Resource(
        uri="file://prompts/prompt-waf.txt",
        name="WAF Rule Generation Prompt",
        description="Main prompt for generating CrowdSec WAF rules from Nuclei templates",
        mimeType="text/plain",
    ),
    types.Resource(
        uri="file://prompts/prompt-waf-examples.txt",
        name="WAF Rule Examples",
        description="Examples of WAF rule generation for CrowdSec",
        mimeType="text/plain",
    ),
    types.Resource(
        uri="file://prompts/prompt-waf-deploy.txt",
        name="WAF Rule Deployment Guide",
        description="Step-by-step guide for deploying CrowdSec WAF rules",
        mimeType="text/plain",
    ),
    types.Resource(
        uri="file://prompts/prompt-waf-tests.txt",
        name="WAF Test Generation Prompt",
        description="Instructions for producing config.yaml and adapted Nuclei templates for WAF testing",
        mimeType="text/plain",
    ),
]

WAF_RESOURCE_READERS: dict[str, Callable[[], str]] = {
    "file://prompts/prompt-waf-top-level.txt": lambda: WAF_TOP_LEVEL_PROMPT_FILE.read_text(encoding="utf-8"),
    "file://prompts/prompt-waf.txt": lambda: WAF_PROMPT_FILE.read_text(encoding="utf-8"),
    "file://prompts/prompt-waf-examples.txt": lambda: WAF_EXAMPLES_FILE.read_text(encoding="utf-8"),
    "file://prompts/prompt-waf-deploy.txt": lambda: WAF_DEPLOY_FILE.read_text(encoding="utf-8"),
    "file://prompts/prompt-waf-tests.txt": lambda: WAF_TESTS_PROMPT_FILE.read_text(encoding="utf-8"),
}

REGISTRY.register_tools(WAF_TOOL_HANDLERS, WAF_TOOLS)
REGISTRY.register_resources(WAF_RESOURCES, WAF_RESOURCE_READERS)
