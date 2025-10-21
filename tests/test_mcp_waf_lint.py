import sys
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_DIR))

try:
    from crowdsec_local_mcp.mcp_waf import _lint_waf_rule
except ModuleNotFoundError as exc:
    raise ImportError(
        "Required modules for testing are missing. "
        "Please ensure that all dependencies are installed."
    ) from exc

def _lint_output(rule_yaml: str) -> str:
    """Join the lint output text for easier assertions in tests."""
    result = _lint_waf_rule(rule_yaml)
    return "\n".join(content.text for content in result)


class TestLintWafRule(unittest.TestCase):
    def test_mixing_and_or_same_level_triggers_warning(self) -> None:
        rule_yaml = """
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
        output = _lint_output(rule_yaml)
        self.assertIn("uses both 'and' and 'or' operators", output)
    def test_case_sensitivity(self) -> None:
        rule_yaml = """
name: xx/xx
description: 'xxx'
rules:
  - and:
      - zones:
          - URI
        match:
          type: regex
          value: '^/PRODUCTS/[0-9]+/?$'
"""
        output = _lint_output(rule_yaml)
        self.assertIn(
            "uses 'regex' with uppercase letters but no 'lowercase' transform",
            output,
        )

if __name__ == "__main__":
    unittest.main()
