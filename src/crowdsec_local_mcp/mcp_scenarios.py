from pathlib import Path
from typing import Any
from collections.abc import Callable
import json
import subprocess
import time

import jsonschema
import yaml

from mcp import types

from .mcp_core import LOGGER, PROMPTS_DIR, REGISTRY, SCRIPT_DIR, ToolHandler
from .utils import detect_compose_command

SCENARIO_PROMPT_FILE = PROMPTS_DIR / "prompt-scenario.txt"
SCENARIO_EXAMPLES_FILE = PROMPTS_DIR / "prompt-scenario-examples.txt"
SCENARIO_SCHEMA_FILE = SCRIPT_DIR / "yaml-schemas" / "scenario_schema.yaml"
SCENARIO_DEPLOY_PROMPT_FILE = PROMPTS_DIR / "prompt-scenario-deploy.txt"
SCENARIO_EXPR_HELPERS_PROMPT_FILE = PROMPTS_DIR / "prompt-expr-helpers.txt"
SCENARIO_COMPOSE_DIR = SCRIPT_DIR / "compose" / "scenario-test"
SCENARIO_COMPOSE_FILE = SCENARIO_COMPOSE_DIR / "docker-compose.yml"
SCENARIO_PROJECT_NAME = "crowdsec-mcp-scenario"

REQUIRED_SCENARIO_FIELDS = ["name", "description", "type"]
EXPECTED_TYPE_VALUES = {"leaky", "trigger", "counter", "conditional", "bayesian"}
RECOMMENDED_FIELDS = ["filter", "groupby", "leakspeed", "capacity", "labels"]
_SCENARIO_SCHEMA_CACHE: dict[str, Any] | None = None


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_scenario_schema() -> dict[str, Any]:
    global _SCENARIO_SCHEMA_CACHE
    if _SCENARIO_SCHEMA_CACHE is not None:
        return _SCENARIO_SCHEMA_CACHE

    if not SCENARIO_SCHEMA_FILE.exists():
        raise FileNotFoundError(f"Scenario schema not found at {SCENARIO_SCHEMA_FILE}")

    LOGGER.info("Loading scenario JSON schema from %s", SCENARIO_SCHEMA_FILE)
    schema = yaml.safe_load(SCENARIO_SCHEMA_FILE.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        raise ValueError("Scenario schema file did not contain a valid mapping")
    _SCENARIO_SCHEMA_CACHE = schema
    return schema


def _tool_get_scenario_prompt(_: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        LOGGER.info("Serving scenario authoring prompt content")
        return [
            types.TextContent(
                type="text",
                text=_read_text(SCENARIO_PROMPT_FILE),
            )
        ]
    except FileNotFoundError:
        LOGGER.error("Scenario prompt file not found at %s", SCENARIO_PROMPT_FILE)
        return [
            types.TextContent(
                type="text",
                text="Error: Scenario authoring prompt file not found.",
            )
        ]
    except Exception as exc:
        LOGGER.error("Error reading scenario prompt: %s", exc)
        return [
            types.TextContent(
                type="text",
                text=f"Error reading scenario prompt: {exc!s}",
            )
        ]


def _tool_get_scenario_examples(_: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        LOGGER.info("Serving scenario example bundle")
        return [
            types.TextContent(
                type="text",
                text=_read_text(SCENARIO_EXAMPLES_FILE),
            )
        ]
    except FileNotFoundError:
        LOGGER.error("Scenario examples missing at %s", SCENARIO_EXAMPLES_FILE)
        return [
            types.TextContent(
                type="text",
                text="Error: Scenario examples file not found.",
            )
        ]
    except Exception as exc:
        LOGGER.error("Error reading scenario examples: %s", exc)
        return [
            types.TextContent(
                type="text",
                text=f"Error reading scenario examples: {exc!s}",
            )
        ]
    
def _tool_get_expr_helpers(_: dict[str, Any] | None) -> list[types.TextContent]:
    try:
        LOGGER.info("Serving scenario expression helpers bundle")
        return [
            types.TextContent(
                type="text",
                text=_read_text(SCENARIO_EXPR_HELPERS_PROMPT_FILE),
            )
        ]
    except FileNotFoundError:
        LOGGER.error("Scenario expression helpers missing at %s", SCENARIO_EXPR_HELPERS_PROMPT_FILE)
        return [
            types.TextContent(
                type="text",
                text="Error: Scenario expression helpers file not found.",
            )
        ]
    except Exception as exc:
        LOGGER.error("Error reading scenario expression helpers: %s", exc)
        return [
            types.TextContent(
                type="text",
                text=f"Error reading scenario expression helpers: {exc!s}",
            )
        ]


def _validate_scenario_yaml(raw_yaml: str) -> dict[str, Any]:
    """Return parsed scenario YAML or raise ValueError on validation failure."""
    try:
        parsed = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        raise ValueError(f"YAML syntax error: {exc}") from exc

    if parsed is None:
        raise ValueError("Empty YAML content")

    if not isinstance(parsed, dict):
        raise ValueError("Scenario YAML must define a mapping at the top level")

    try:
        schema = _load_scenario_schema()
    except FileNotFoundError as exc:
        LOGGER.error("Scenario schema missing: %s", exc)
        raise ValueError(f"Schema file missing: {exc}") from exc
    except Exception as exc:
        LOGGER.error("Failed to load scenario schema: %s", exc)
        raise ValueError(f"Unable to load scenario schema: {exc}") from exc

    try:
        jsonschema.validate(instance=parsed, schema=schema)
    except jsonschema.ValidationError as exc:
        path = " -> ".join(str(p) for p in exc.absolute_path) or "root"
        raise ValueError(f"Schema validation error at {path}: {exc.message}") from exc
    except jsonschema.SchemaError as exc:
        LOGGER.error("Scenario schema is invalid: %s", exc)
        raise ValueError(f"Scenario schema is invalid: {exc}") from exc

    missing = [field for field in REQUIRED_SCENARIO_FIELDS if field not in parsed]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")

    scenario_type = parsed.get("type")
    if not isinstance(scenario_type, str):
        raise ValueError("Field 'type' must be a string")

    if scenario_type not in EXPECTED_TYPE_VALUES:
        LOGGER.warning("Scenario type %s is not in the recognised set %s", scenario_type, EXPECTED_TYPE_VALUES)

    labels = parsed.get("labels")
    if labels is not None and not isinstance(labels, dict):
        raise ValueError("Field 'labels' must be a dictionary when present")

    return parsed


def _tool_validate_scenario(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    if not arguments or "scenario_yaml" not in arguments:
        LOGGER.warning("Scenario validation requested without 'scenario_yaml'")
        return [
            types.TextContent(
                type="text",
                text="Error: scenario_yaml parameter is required",
            )
        ]

    raw_yaml = arguments["scenario_yaml"]
    LOGGER.info("Validating CrowdSec scenario YAML submission")
    try:
        parsed = _validate_scenario_yaml(raw_yaml)
        scenario_type = parsed.get("type", "unknown")
        return [
            types.TextContent(
                type="text",
                text=f"✅ VALIDATION PASSED: Scenario type `{scenario_type}` conforms to schema.",
            )
        ]
    except ValueError as exc:
        return [
            types.TextContent(
                type="text",
                text=f"❌ VALIDATION FAILED: {exc!s}",
            )
        ]


def _tool_lint_scenario(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    if not arguments or "scenario_yaml" not in arguments:
        LOGGER.warning("Scenario lint requested without 'scenario_yaml'")
        return [
            types.TextContent(
                type="text",
                text="Error: scenario_yaml parameter is required",
            )
        ]

    raw_yaml = arguments["scenario_yaml"]
    LOGGER.info("Linting CrowdSec scenario YAML submission")

    try:
        parsed = _validate_scenario_yaml(raw_yaml)
    except ValueError as exc:
        return [
            types.TextContent(
                type="text",
                text=f"❌ LINT ERROR: {exc!s}",
            )
        ]

    warnings: list[str] = []
    hints: list[str] = []

    scenario_type = parsed.get("type")
    if isinstance(scenario_type, str) and scenario_type not in EXPECTED_TYPE_VALUES:
        warnings.append(
            f"Scenario type '{scenario_type}' is unusual; expected one of {', '.join(sorted(EXPECTED_TYPE_VALUES))}."
        )

    for field in RECOMMENDED_FIELDS:
        if field not in parsed:
            hints.append(f"Consider adding '{field}' to improve scenario behaviour visibility.")

    if "groupby" in parsed and not isinstance(parsed["groupby"], str):
        warnings.append("Field 'groupby' should be a string expr that partitions buckets.")

    if "filter" in parsed and not isinstance(parsed["filter"], str):
        warnings.append("Field 'filter' should be a string expression.")

    if "distinct" in parsed and not isinstance(parsed["distinct"], str):
        warnings.append("Field 'distinct' should be a string expr returning a unique key.")

    if "format" in parsed and parsed.get("format") not in (None, 2.0):
        hints.append("Set `format: 2.0` to align with current scenario compatibility guidance.")

    if "labels" in parsed and parsed.get("labels"):
        label_values = parsed["labels"]
        if isinstance(label_values, dict):
            missing_values = [k for k, v in label_values.items() if not v]
            if missing_values:
                hints.append(
                    f"Provide values for label(s): {', '.join(missing_values)} for better observability."
                )

    result_lines: list[str] = []

    if warnings:
        result_lines.append("⚠️  WARNINGS:")
        for item in warnings:
            result_lines.append(f"  - {item}")

    if hints:
        if warnings:
            result_lines.append("")
        result_lines.append("💡 HINTS:")
        for item in hints:
            result_lines.append(f"  - {item}")

    if not result_lines:
        result_lines.append("✅ LINT PASSED: No structural issues detected.")

    return [
        types.TextContent(
            type="text",
            text="\n".join(result_lines),
        )
    ]


def _tool_deploy_scenario(_: dict[str, Any] | None) -> list[types.TextContent]:
    LOGGER.info("Serving scenario deployment helper prompt")
    try:
        return [
            types.TextContent(
                type="text",
                text=_read_text(SCENARIO_DEPLOY_PROMPT_FILE),
            )
        ]
    except FileNotFoundError:
        LOGGER.error("Scenario deployment prompt missing at %s", SCENARIO_DEPLOY_PROMPT_FILE)
        return [
            types.TextContent(
                type="text",
                text="Error: Scenario deployment prompt file not found.",
            )
        ]
    except Exception as exc:
        LOGGER.error("Failed to load scenario deployment prompt: %s", exc)
        return [
            types.TextContent(
                type="text",
                text=f"Error reading scenario deployment prompt: {exc!s}",
            )
        ]

def _run_scenario_compose_command(
    args: list[str],
    capture_output: bool = True,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess:
    """Run a docker compose command within the scenario test harness directory."""
    if not SCENARIO_COMPOSE_FILE.exists():
        raise RuntimeError(
            f"Scenario docker-compose file not found at {SCENARIO_COMPOSE_FILE}"
        )

    base_cmd = detect_compose_command()
    full_cmd = base_cmd + ["-p", SCENARIO_PROJECT_NAME, "-f", str(SCENARIO_COMPOSE_FILE)] + args
    LOGGER.info("Executing scenario compose command: %s", " ".join(full_cmd))

    try:
        return subprocess.run(
            full_cmd,
            cwd=str(SCENARIO_COMPOSE_DIR),
            capture_output=capture_output,
            text=True,
            check=check,
            input=input_text,
        )
    except FileNotFoundError as error:
        LOGGER.error("Scenario compose command failed to start: %s", error)
        raise RuntimeError(f"Failed to run {' '.join(base_cmd)}: {error}") from error
    except subprocess.CalledProcessError as error:
        stdout = (error.stdout or "").strip()
        stderr = (error.stderr or "").strip()
        combined = "\n".join(part for part in (stdout, stderr) if part) or str(error)
        LOGGER.error(
            "Scenario compose command exited with %s: %s",
            error.returncode,
            combined.splitlines()[0] if combined else "no output",
        )
        raise RuntimeError(
            f"docker compose {' '.join(args)} failed (exit code {error.returncode}):\n{combined}"
        ) from error

def _run_scenario_compose_exec(
    args: list[str],
    capture_output: bool = True,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess:
    """Run docker compose exec against the CrowdSec scenario container."""
    exec_args = ["exec", "-T"] + args
    return _run_scenario_compose_command(
        exec_args,
        capture_output=capture_output,
        check=check,
        input_text=input_text,
    )

def _compose_stack_running() -> bool:
    if not SCENARIO_COMPOSE_FILE.exists():
        LOGGER.warning(
            "Scenario stack status requested but compose file missing at %s", SCENARIO_COMPOSE_FILE
        )
        return False

    result = _run_scenario_compose_command(["ps", "-q"], capture_output=True, check=False)
    if result.returncode != 0:
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
        raise RuntimeError(
            f"docker compose ps failed (exit code {result.returncode}):\n{combined}"
        )
    return bool((result.stdout or "").strip())

def _compose_stack_start() -> bool:
    if _compose_stack_running():
        LOGGER.info("Scenario stack already running; skipping start request")
        return False

    LOGGER.info("Starting scenario test stack")
    _run_scenario_compose_command(["up", "-d"], capture_output=True, check=True)
    return True

def _compose_stack_stop() -> None:
    if not SCENARIO_COMPOSE_FILE.exists():
        LOGGER.warning(
            "Scenario stack stop requested but compose file missing at %s", SCENARIO_COMPOSE_FILE
        )
        return

    LOGGER.info("Stopping scenario test stack")
    _run_scenario_compose_command(["down"], capture_output=True, check=True)

def _compose_stack_reload_crowdsec() -> None:
    if not _compose_stack_running():
        raise RuntimeError("Scenario stack is not running; start it before reloading CrowdSec.")

    LOGGER.info("Reloading CrowdSec process inside scenario test stack")
    result = _run_scenario_compose_command(
        ["exec", "-T", "crowdsec", "sh", "-c", "kill -HUP 1"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
        raise RuntimeError(
            f"Failed to reload CrowdSec via SIGHUP (exit code {result.returncode}):\n{combined}"
        )

#ruff: noqa: RUF001
def _tool_manage_scenario_stack(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    if not arguments:
        LOGGER.warning("manage_scenario_stack called without arguments")
        raise ValueError("Missing arguments payload")

    action = arguments.get("action")
    if action not in {"start", "stop", "reload"}:
        LOGGER.warning("manage_scenario_stack received invalid action: %s", action)
        raise ValueError("Action must be one of: start, stop, reload")

    if action == "start":
        started = _compose_stack_start()
        message = (
            "✅ Scenario stack started. CrowdSec container is running."
            if started
            else "ℹ️ Scenario stack already running; reusing existing containers."
        )
        return [types.TextContent(type="text", text=message)]

    if action == "stop":
        if _compose_stack_running():
            _compose_stack_stop()
            message = "🛑 Scenario stack stopped and containers removed."
        else:
            LOGGER.info("Scenario stack stop requested but stack was not running")
            _compose_stack_stop()
            message = "ℹ️ Scenario stack was already stopped."
        return [types.TextContent(type="text", text=message)]

    _compose_stack_reload_crowdsec()
    return [
        types.TextContent(
            type="text",
            text="🔄 CrowdSec process reloaded inside the scenario stack.",
        )
    ]


def _tool_explain_scenario(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    required_keys = {"scenario_yaml", "log_line", "log_type", "collections"}
    if not arguments:
        LOGGER.warning("Scenario explanation requested without arguments")
        raise ValueError("Arguments are required for scenario explanation")

    missing = required_keys.difference(arguments.keys())
    if missing:
        LOGGER.warning("Scenario explanation missing required keys: %s", ", ".join(sorted(missing)))
        raise ValueError(
            "scenario_yaml, log_line, log_type, and collections are required arguments"
        )

    scenario_yaml = arguments.get("scenario_yaml")
    log_line = arguments.get("log_line")
    log_type = arguments.get("log_type")
    collections = arguments.get("collections")

    if not isinstance(scenario_yaml, str) or not scenario_yaml.strip():
        raise ValueError("'scenario_yaml' must be a non-empty string")
    if not isinstance(log_line, str) or not log_line.strip():
        raise ValueError("'log_line' must be a non-empty string")
    if not isinstance(log_type, str) or not log_type.strip():
        raise ValueError("'log_type' must be a non-empty string")
    if not isinstance(collections, list) or not all(isinstance(c, str) and c.strip() for c in collections):
        raise ValueError("'collections' must be a list of non-empty strings")

    if not _compose_stack_running():
        LOGGER.warning("Scenario explain requested but stack is not running")
        raise RuntimeError("Scenario stack is not running. Start it with manage_scenario_stack(action='start').")

    scenario_path = SCENARIO_COMPOSE_DIR / "scenarios" / "custom.yaml"
    scenario_path.parent.mkdir(parents=True, exist_ok=True)
    scenario_path.write_text(scenario_yaml, encoding="utf-8")
    LOGGER.info("Wrote scenario YAML to %s", scenario_path)

    for collection in collections:
        collection_name = collection.strip()
        LOGGER.info("Installing collection %s for scenario explain", collection_name)
        install_result = _run_scenario_compose_exec(
            ["crowdsec", "cscli", "collections", "install", collection_name],
            capture_output=True,
            check=False,
        )
        if install_result.returncode != 0:
            stdout = (install_result.stdout or "").strip()
            stderr = (install_result.stderr or "").strip()
            combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
            LOGGER.error("Collection install failed for %s: %s", collection_name, combined)
            raise RuntimeError(
                f"Failed to install collection '{collection_name}' (exit code {install_result.returncode}):\n{combined}"
            )

    _compose_stack_reload_crowdsec()
    LOGGER.info("Waiting for CrowdSec reload to settle")
    time.sleep(3)

    LOGGER.info("Executing cscli explain with provided log line and type")
    explain_result = _run_scenario_compose_exec(
        ["crowdsec", "cscli", "explain", "--log", log_line.strip(), "--type", log_type.strip(), "-v"],
        capture_output=True,
        check=False,
    )

    stdout = (explain_result.stdout or "").strip()
    stderr = (explain_result.stderr or "").strip()
    combined_output = "\n".join(part for part in (stdout, stderr) if part).strip()

    if explain_result.returncode != 0:
        message = combined_output or f"cscli explain failed with exit code {explain_result.returncode}"
        LOGGER.error("cscli explain failed: %s", message)
        raise RuntimeError(message)

    response_text = combined_output or "cscli explain completed with no output."
    return [
        types.TextContent(
            type="text",
            text=f"✅ cscli explain succeeded:\n{response_text}",
        )
    ]

#ruff: noqa: PLR0912
#ruff: noqa: PLR0915
def _tool_test_scenario(arguments: dict[str, Any] | None) -> list[types.TextContent]:
    required_keys = {"scenario_yaml", "log_lines", "log_type"}
    if not arguments:
        LOGGER.warning("Scenario test requested without arguments")
        raise ValueError("Arguments are required for scenario testing")

    missing = required_keys.difference(arguments.keys())
    if missing:
        LOGGER.warning("Scenario test missing required keys: %s", ", ".join(sorted(missing)))
        raise ValueError("scenario_yaml, log_lines, and log_type are required arguments")

    scenario_yaml = arguments.get("scenario_yaml")
    log_lines_arg = arguments.get("log_lines")
    log_type = arguments.get("log_type")
    collections = arguments.get("collections")

    if not isinstance(scenario_yaml, str) or not scenario_yaml.strip():
        raise ValueError("'scenario_yaml' must be a non-empty string")
    if isinstance(log_lines_arg, str):
        if not log_lines_arg.strip():
            raise ValueError("'log_lines' must contain at least one non-empty log line")
        log_lines = [log_lines_arg]
    elif (
        isinstance(log_lines_arg, list)
        and log_lines_arg
        and all(isinstance(line, str) and line.strip() for line in log_lines_arg)
    ):
        log_lines = log_lines_arg
    else:
        raise ValueError("'log_lines' must be a non-empty string or list of non-empty strings")
    if not isinstance(log_type, str) or not log_type.strip():
        raise ValueError("'log_type' must be a non-empty string")
    if collections is None:
        raise ValueError("'collections' must be provided and contain at least one collection name")
    if isinstance(collections, str):
        if not collections.strip():
            raise ValueError("'collections' must contain at least one non-empty collection name")
        collections_list = [collections.strip()]
    else:
        if not isinstance(collections, list) or not collections:
            raise ValueError("'collections' must be a non-empty string or list of non-empty strings")
        if not all(isinstance(item, str) and item.strip() for item in collections):
            raise ValueError("'collections' must be a non-empty string or list of non-empty strings")
        collections_list = [item.strip() for item in collections if isinstance(item, str)]

    if not _compose_stack_running():
        LOGGER.warning("Scenario test requested but stack is not running")
        raise RuntimeError("Scenario stack is not running. Start it with manage_scenario_stack(action='start').")

    scenario_path = SCENARIO_COMPOSE_DIR / "scenarios" / "custom.yaml"
    scenario_path.parent.mkdir(parents=True, exist_ok=True)
    scenario_path.write_text(scenario_yaml, encoding="utf-8")
    LOGGER.info("Scenario under test written to %s", scenario_path)

    reload_required = False
    for collection in collections_list:
        collection_name = collection.strip()
        LOGGER.info("Installing collection %s for scenario test", collection_name)
        install_result = _run_scenario_compose_exec(
            ["crowdsec", "cscli", "collections", "install", collection_name],
            capture_output=True,
            check=False,
        )
        if install_result.returncode != 0:
            stdout = (install_result.stdout or "").strip()
            stderr = (install_result.stderr or "").strip()
            combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
            LOGGER.error("Failed to install collection %s: %s", collection_name, combined)
            raise RuntimeError(
                f"Failed to install collection '{collection_name}' (exit code {install_result.returncode}):\n{combined}"
            )
        combined_output = "\n".join(
            part.strip()
            for part in ((install_result.stdout or ""), (install_result.stderr or ""))
            if part
        ).lower()
        if not ("already" in combined_output and "installed" in combined_output):
            reload_required = True

    if reload_required:
        _compose_stack_reload_crowdsec()
        LOGGER.info("Waiting for CrowdSec reload post collection install")
        time.sleep(3)

    # ruff: noqa: S108
    mktemp_result = _run_scenario_compose_exec(
        ["crowdsec", "mktemp", "/tmp/mcp-scenario-logs.XXXXXX"],
        capture_output=True,
        check=False,
    )
    if mktemp_result.returncode != 0:
        stdout = (mktemp_result.stdout or "").strip()
        stderr = (mktemp_result.stderr or "").strip()
        combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
        LOGGER.error("mktemp failed: %s", combined)
        raise RuntimeError(f"Failed to create temporary logs file: {combined}")
    temp_path = (mktemp_result.stdout or "").strip()
    if not temp_path:
        raise RuntimeError("mktemp did not return a temporary file path")

    log_payload = "".join(line.rstrip("\n") + "\n" for line in log_lines)
    write_result = _run_scenario_compose_exec(
        ["crowdsec", "sh", "-c", f"cat > {temp_path}"],
        capture_output=True,
        check=False,
        input_text=log_payload,
    )
    if write_result.returncode != 0:
        stdout = (write_result.stdout or "").strip()
        stderr = (write_result.stderr or "").strip()
        combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
        LOGGER.error("Failed to write log payload to %s: %s", temp_path, combined)
        raise RuntimeError(f"Failed to write log payload to {temp_path}: {combined}")

    try:
        delete_result = _run_scenario_compose_exec(
            ["crowdsec", "cscli", "alerts", "delete", "--all"],
            capture_output=True,
            check=False,
        )
        if delete_result.returncode != 0:
            stdout = (delete_result.stdout or "").strip()
            stderr = (delete_result.stderr or "").strip()
            combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
            LOGGER.error("Failed to purge alerts: %s", combined)
            raise RuntimeError(f"Failed to clear existing alerts: {combined}")

        crowdsec_cmd = [
            "crowdsec",
            "crowdsec",
            "--dsn",
            f"file://{temp_path}",
            "--type",
            log_type.strip(),
            "-no-api",
        ]
        LOGGER.info("Running CrowdSec replay command: %s", " ".join(crowdsec_cmd))
        crowdsec_result = _run_scenario_compose_exec(
            crowdsec_cmd,
            capture_output=True,
            check=False,
        )
        if crowdsec_result.returncode != 0:
            stdout = (crowdsec_result.stdout or "").strip()
            stderr = (crowdsec_result.stderr or "").strip()
            combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
            LOGGER.error("CrowdSec replay failed: %s", combined)
            raise RuntimeError(
                f"CrowdSec replay failed (exit code {crowdsec_result.returncode}):\n{combined}"
            )

        alerts_result = _run_scenario_compose_exec(
            ["crowdsec", "cscli", "alerts", "list", "-o", "json"],
            capture_output=True,
            check=False,
        )
        if alerts_result.returncode != 0:
            stdout = (alerts_result.stdout or "").strip()
            stderr = (alerts_result.stderr or "").strip()
            combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
            LOGGER.error("Failed to list alerts: %s", combined)
            raise RuntimeError(f"Failed to list alerts: {combined}")

        alerts_output = (alerts_result.stdout or "").strip()
        try:
            alerts_json = json.loads(alerts_output) if alerts_output else []
        except json.JSONDecodeError as exc:
            LOGGER.error("Failed to decode alerts JSON: %s", exc)
            raise RuntimeError(f"alerts list returned invalid JSON: {exc}") from exc

        rendered_alerts = json.dumps(alerts_json, indent=2)
        LOGGER.info("Scenario test produced alerts: %s", rendered_alerts)
        return [
            types.TextContent(
                type="text",
                text=f"✅ Scenario test completed. Alerts:\n{rendered_alerts}",
            )
        ]
    finally:
        cleanup_result = _run_scenario_compose_exec(
            ["crowdsec", "rm", "-f", temp_path],
            capture_output=True,
            check=False,
        )
        if cleanup_result.returncode != 0:
            stdout = (cleanup_result.stdout or "").strip()
            stderr = (cleanup_result.stderr or "").strip()
            combined = "\n".join(part for part in (stdout, stderr) if part) or "no output"
            LOGGER.warning("Failed to remove temp file %s: %s", temp_path, combined)


SCENARIO_TOOL_HANDLERS: dict[str, ToolHandler] = {
    "get_scenario_prompt": _tool_get_scenario_prompt,
    "get_scenario_examples": _tool_get_scenario_examples,
    "validate_scenario_yaml": _tool_validate_scenario,
    "lint_scenario_yaml": _tool_lint_scenario,
    "deploy_scenario": _tool_deploy_scenario,
    "explain_scenario": _tool_explain_scenario,
    "manage_scenario_stack": _tool_manage_scenario_stack,
    "test_scenario": _tool_test_scenario,
    "get_scenario_expr_helpers": _tool_get_expr_helpers,
}

SCENARIO_TOOLS: list[types.Tool] = [
    types.Tool(
        name="get_scenario_prompt",
        description="Retrieve the base prompt for authoring CrowdSec scenarios",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_scenario_examples",
        description="Retrieve example CrowdSec scenarios and annotations",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="get_scenario_expr_helpers",
        description="Retrieve helper expressions for CrowdSec scenario authoring",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="validate_scenario_yaml",
        description="Validate CrowdSec scenario YAML structure for required fields",
        inputSchema={
            "type": "object",
            "properties": {
                "scenario_yaml": {
                    "type": "string",
                    "description": "Scenario YAML to validate",
                },
            },
            "required": ["scenario_yaml"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="lint_scenario_yaml",
        description="Lint CrowdSec scenario YAML and highlight potential improvements",
        inputSchema={
            "type": "object",
            "properties": {
                "scenario_yaml": {
                    "type": "string",
                    "description": "Scenario YAML to lint",
                },
            },
            "required": ["scenario_yaml"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="deploy_scenario",
        description="Retrieve guidance for packaging and deploying a CrowdSec scenario",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="manage_scenario_stack",
        description="Manage the lifecycle of the scenario testing stack (ONLY USE FOR TESTING SCENARIOS)",
        inputSchema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "reload"],
                    "description": "Action to perform on the scenario testing stack",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="explain_scenario",
        description="""
        Shows how crowdsec processes a single log line: what is extracted by the parsers, and which scenarios match.
        A match does not mean an alert is generated, only that the event was of interest for the scenario.
        This tool MUST NEVER be called with multiple log lines. If you need to test whether a scenario generates an alert, use the `test_scenario` tool instead.
        """,
        inputSchema={
            "type": "object",
            "properties": {
                "scenario_yaml": {
                    "type": "string",
                    "description": "Scenario YAML to explain",
                },
                "log_type": {
                    "type": "string",
                    "description": "Type of logs the scenario is intended to analyze",
                },
                "collections": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of CrowdSec collections to install alongside the scenario",
                },
                "log_line": {
                    "type": "string",
                    "description": "A single example log line that should trigger the scenario",
                },
            },
            "required": ["scenario_yaml", "log_line", "log_type", "collections"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="test_scenario",
        description="""
        Test a CrowdSec scenario against multiple log lines (effectively replaying the events as if they were occurring in real-time).
        """,
        inputSchema={
            "type": "object",
            "properties": {
                "scenario_yaml": {
                    "type": "string",
                    "description": "Scenario YAML to test",
                },
                "log_lines": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of log lines to test against the scenario",
                },
                "log_type": {
                    "type": "string",
                    "description": "Type of logs the scenario is intended to analyze",
                },
                "collections": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of CrowdSec collections to install alongside the scenario",
                },
            },
            "required": ["scenario_yaml", "log_lines", "log_type", "collections"],
            "additionalProperties": False,
        },
    ),
]

SCENARIO_RESOURCES: list[types.Resource] = [
    types.Resource(
        uri="file://prompts/prompt-scenario.txt",
        name="Scenario Authoring Prompt",
        description="Foundation prompt to guide the authoring of CrowdSec detection scenarios",
        mimeType="text/plain",
    ),
    types.Resource(
        uri="file://prompts/prompt-scenario-examples.txt",
        name="Scenario Examples",
        description="Worked scenario examples with callouts",
        mimeType="text/plain",
    ),
    types.Resource(
        uri="file://prompts/prompt-scenario-deploy.txt",
        name="Scenario Deployment Helper",
        description="Guidance for packaging and deploying CrowdSec scenarios to local or hub environments",
        mimeType="text/plain",
    ),
    types.Resource(
        uri="file://prompts/prompt-expr-helpers.txt",
        name="Scenario Expression Helpers",
        description="List of supported expression helpers when writing CrowdSec scenarios",
        mimeType="text/plain",
    ),
]

SCENARIO_RESOURCE_READERS: dict[str, Callable[[], str]] = {
    "file://prompts/prompt-scenario.txt": lambda: _read_text(SCENARIO_PROMPT_FILE),
    "file://prompts/prompt-scenario-examples.txt": lambda: _read_text(SCENARIO_EXAMPLES_FILE),
    "file://prompts/prompt-scenario-deploy.txt": lambda: _read_text(SCENARIO_DEPLOY_PROMPT_FILE),
    "file://prompts/prompt-expr-helpers.txt": lambda: _read_text(SCENARIO_EXPR_HELPERS_PROMPT_FILE),
}

REGISTRY.register_tools(SCENARIO_TOOL_HANDLERS, SCENARIO_TOOLS)
REGISTRY.register_resources(SCENARIO_RESOURCES, SCENARIO_RESOURCE_READERS)
