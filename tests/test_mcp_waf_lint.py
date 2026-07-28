from __future__ import annotations

import sys
from pathlib import Path
import textwrap

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:  # pragma: no cover - import guard for optional dependency
    from crowdsec_local_mcp.mcp_waf import lint_waf_rule, _validate_waf_rule
except ModuleNotFoundError as exc:  # pragma: no cover - handled by pytest skip
    pytest.skip(
        reason=f"crowdsec_local_mcp dependency missing: {exc}",
        allow_module_level=True,
    )

def lint_output(rule_yaml: str) -> str:
    result = lint_waf_rule(rule_yaml)
    return "\n".join(content.text for content in result)


def test_double_quote_value_warned() -> None:
    """A raw double-quote in a match value is flagged in favour of \\x22."""
    rule_yaml = textwrap.dedent(
        """
        name: mycompany/vpatch-xss-comment
        description: 'Detects a double-quote in the comment parameter'
        rules:
          - zones:
              - ARGS
            variables:
              - comment
            transform:
              - lowercase
              - urldecode
            match:
              type: contains
              value: '"'
        """
    ).strip()

    output = lint_output(rule_yaml)
    assert "\\x22" in output # noqa: S101


def test_same_level_and_or_rejected_by_schema() -> None:
    """A single block carrying both `and` and `or` is invalid (schema oneOf)."""
    rule_yaml = textwrap.dedent(
        """
        name: mycompany/test-same-level
        description: 'A single block must not carry both and and or'
        labels:
          type: exploit
        rules:
          - and:
              - zones:
                  - URI
                match:
                  type: contains
                  value: '/a'
            or:
              - zones:
                  - URI
                match:
                  type: contains
                  value: '/b'
        """
    ).strip()

    with pytest.raises(ValueError):
        _validate_waf_rule(rule_yaml)


def test_case_sensitivity_warning() -> None:
    rule_yaml = textwrap.dedent(
        """
        name: mycompany/test-case-sensitivity
        description: 'Ensure uppercase regex triggers lowercase transform warning'
        rules:
          - match:
              type: regex
              value: '^/PRODUCTS/[0-9]+/?$'
        """
    ).strip()

    output = lint_output(rule_yaml)
    assert "uses 'regex' with uppercase letters but no 'lowercase' transform" in output # noqa: S101
