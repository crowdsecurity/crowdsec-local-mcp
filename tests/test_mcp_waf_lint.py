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
    from crowdsec_local_mcp.mcp_waf import lint_waf_rule, validate_waf_rule
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


def test_same_level_and_or_accepted_by_schema() -> None:
    """A single block may carry both `and` and `or`; the engine flattens it to DNF."""
    rule_yaml = textwrap.dedent(
        """
        name: mycompany/test-same-level
        description: 'A single block may carry both and and or'
        labels:
          type: exploit
          service: http
          behavior: 'http:exploit'
          confidence: 3
          spoofable: 0
          classification:
            - cve.CVE-2026-0001
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

    validate_waf_rule(rule_yaml)


def test_unknown_field_rejected_by_schema() -> None:
    """A misspelt field is fatal to the engine, so the schema has to catch it."""
    rule_yaml = textwrap.dedent(
        """
        name: mycompany/test-typo
        description: 'tranform is not transform'
        labels:
          type: exploit
        rules:
          - zones:
              - URI
            tranform:
              - lowercase
            match:
              type: contains
              value: '/a'
        """
    ).strip()

    with pytest.raises(ValueError, match="Schema validation error"):
        validate_waf_rule(rule_yaml)


def test_expanded_vocabulary_accepted_by_schema() -> None:
    """Zones, transforms and match types the engine gained are no longer rejected."""
    rule_yaml = textwrap.dedent(
        """
        name: mycompany/test-vocabulary
        description: 'Exercises vocabulary added after the schema was first written'
        labels:
          type: exploit
          service: http
          behavior: 'http:exploit'
          confidence: 3
          spoofable: 0
          classification:
            - cve.CVE-2026-0001
        rules:
          - and:
              - zones:
                  - METHOD
                match:
                  type: equals
                  value: 'POST'
              - zones:
                  - BODY_ARGS
                variables:
                  - payload
                transform:
                  - b64decode_lenient
                  - compress_whitespaces
                  - remove_comments
                body_type: json
                match:
                  type: contains
                  value: 'exec('
                  not: true
        """
    ).strip()

    validate_waf_rule(rule_yaml)


def test_unquoted_match_value_warned() -> None:
    """An unquoted `off` becomes a bool in YAML, so the linter asks for quotes."""
    rule_yaml = textwrap.dedent(
        """
        name: mycompany/test-unquoted
        description: 'An unquoted off reads as a boolean'
        labels:
          type: exploit
        rules:
          - zones:
              - HEADERS
            variables:
              - x-auth-check
            match:
              type: equals
              value: off
        """
    ).strip()

    assert "quote it so it stays the string" in lint_output(rule_yaml)  # noqa: S101


def test_numeric_match_value_not_warned() -> None:
    """A numeric comparison is meant to carry a number; it must not be flagged."""
    rule_yaml = textwrap.dedent(
        """
        name: mycompany/test-count
        description: 'count plus gte is the idiomatic numeric pairing'
        labels:
          type: exploit
        rules:
          - zones:
              - BODY_ARGS
            variables:
              - 'user[email][]'
            transform:
              - count
            match:
              type: gte
              value: 2
        """
    ).strip()

    assert "quote it so it stays the string" not in lint_output(rule_yaml)  # noqa: S101


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
