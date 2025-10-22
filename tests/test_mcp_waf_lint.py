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
    from crowdsec_local_mcp.mcp_waf import lint_waf_rule
except ModuleNotFoundError as exc:  # pragma: no cover - handled by pytest skip
    pytest.skip(
        reason=f"crowdsec_local_mcp dependency missing: {exc}",
        allow_module_level=True,
    )

def lint_output(rule_yaml: str) -> str:
    result = lint_waf_rule(rule_yaml)
    return "\n".join(content.text for content in result)


def test_mixing_and_or_detected() -> None:
    rule_yaml = textwrap.dedent(
        """
        name: mycompany/vpatch-sqli-product-category
        description: 'Detects SQL injection attempts in product_category GET parameter on /products/{number} endpoint'
        rules:
          - and:
              - zones:
                  - URI
                transform:
                  - lowercase
                match:
                  type: regex
                  value: '^/products/[0-9]+/?$'
              - or:
                  - zones:
                      - ARGS
                    variables:
                      - product_category
                    transform:
                      - urldecode
                    match:
                      type: contains
                      value: "'"
                  - zones:
                      - ARGS
                    variables:
                      - product_category
                    transform:
                      - urldecode
                    match:
                      type: contains
                      value: '"'
        """
    ).strip()

    output = lint_output(rule_yaml)
    assert "uses both 'and' and 'or' operators" in output # noqa: S101


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
