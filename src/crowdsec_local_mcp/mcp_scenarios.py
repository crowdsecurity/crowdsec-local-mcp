from pathlib import Path
from typing import Any
from collections.abc import Callable

import jsonschema
import yaml

from mcp import types

from .mcp_core import LOGGER, PROMPTS_DIR, REGISTRY, SCRIPT_DIR, ToolHandler

SCENARIO_PROMPT_FILE = PROMPTS_DIR / "prompt-scenario.txt"
SCENARIO_EXAMPLES_FILE = PROMPTS_DIR / "prompt-scenario-examples.txt"
SCENARIO_SCHEMA_FILE = SCRIPT_DIR / "yaml-schemas" / "scenario_schema.yaml"
SCENARIO_DEPLOY_PROMPT_FILE = PROMPTS_DIR / "prompt-scenario-deploy.txt"

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


SCENARIO_TOOL_HANDLERS: dict[str, ToolHandler] = {
    "get_scenario_prompt": _tool_get_scenario_prompt,
    "get_scenario_examples": _tool_get_scenario_examples,
    "validate_scenario_yaml": _tool_validate_scenario,
    "lint_scenario_yaml": _tool_lint_scenario,
    "deploy_scenario": _tool_deploy_scenario,
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
]

SCENARIO_RESOURCE_READERS: dict[str, Callable[[], str]] = {
    "file://prompts/prompt-scenario.txt": lambda: _read_text(SCENARIO_PROMPT_FILE),
    "file://prompts/prompt-scenario-examples.txt": lambda: _read_text(SCENARIO_EXAMPLES_FILE),
    "file://prompts/prompt-scenario-deploy.txt": lambda: _read_text(SCENARIO_DEPLOY_PROMPT_FILE),
}

REGISTRY.register_tools(SCENARIO_TOOL_HANDLERS, SCENARIO_TOOLS)
REGISTRY.register_resources(SCENARIO_RESOURCES, SCENARIO_RESOURCE_READERS)
