"""Guards for the checks that stand between an invalid rule and the test harness.

The failure these cover: a rule can be validated, then edited, then deployed. Validation
that only runs when the caller asks for it never sees the edited bytes, so the checks
here live on the deploy path itself.
"""

# These gates are deliberately internal - they must not be bypassable through the public
# tool surface - so testing them means reaching for private members.
# ruff: noqa: SLF001

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:  # pragma: no cover - import guard for optional dependency
    from crowdsec_local_mcp import mcp_waf
except ModuleNotFoundError as exc:  # pragma: no cover - handled by pytest skip
    pytest.skip(
        reason=f"crowdsec_local_mcp dependency missing: {exc}",
        allow_module_level=True,
    )


def _rule(value: str) -> str:
    """A schema-complete rule whose only variable is the match value."""
    return textwrap.dedent(
        f"""
        name: mycompany/vpatch-probe
        description: 'gate probe'
        labels:
          type: exploit
          service: http
          behavior: 'http:exploit'
          confidence: 3
          spoofable: 0
          classification:
            - attack.T1190
        rules:
          - zones:
              - ARGS
            variables:
              - comment
            match:
              type: contains
              value: '{value}'
        """
    ).strip()


BAD_RULE = _rule('"><script>')
GOOD_RULE = _rule("\\x22><script>")


@pytest.fixture
def no_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly if anything reaches Docker; the gate must refuse before that."""

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Docker must not be invoked for an invalid rule")

    monkeypatch.setattr(mcp_waf, "_run_compose_command", _boom)
    monkeypatch.setattr(mcp_waf, "_compose_up_with_conflict_recovery", _boom)


@pytest.mark.usefixtures("no_docker")
def test_run_waf_tests_refuses_unvalidated_rule() -> None:
    """The exact regression: an invalid rule must never reach the stack."""
    with pytest.raises(RuntimeError, match="literal double-quote"):
        mcp_waf._tool_run_waf_tests({"rule_yaml": BAD_RULE, "nuclei_yaml": "id: probe"})


@pytest.mark.usefixtures("no_docker")
def test_manage_waf_stack_refuses_unvalidated_rule() -> None:
    with pytest.raises(RuntimeError, match=mcp_waf.RULE_VALIDATION_FAILED):
        mcp_waf._tool_manage_waf_stack({"action": "start", "rule_yaml": BAD_RULE})


@pytest.mark.usefixtures("no_docker")
def test_start_stack_does_not_write_invalid_rule() -> None:
    """A refused rule must not land in the harness directory."""
    before = mcp_waf.WAF_TEST_RULE_PATH.read_text() if mcp_waf.WAF_TEST_RULE_PATH.exists() else None

    target_url, error = mcp_waf._start_waf_test_stack(BAD_RULE)

    assert target_url is None  # noqa: S101
    assert mcp_waf.RULE_VALIDATION_FAILED in (error or "")  # noqa: S101
    after = mcp_waf.WAF_TEST_RULE_PATH.read_text() if mcp_waf.WAF_TEST_RULE_PATH.exists() else None
    assert after == before  # noqa: S101


def test_prepare_waf_pr_refuses_and_writes_nothing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="literal double-quote"):
        mcp_waf._tool_prepare_waf_pr(
            {
                "hub_dir": str(tmp_path),
                "rule_yaml": BAD_RULE,
                "test_config_yaml": "appsec-rules: []",
                "test_nuclei_yaml": "id: probe",
                "rule_filename": "appsec-rules/mycompany/vpatch-probe.yaml",
                "nuclei_filename": "vpatch-probe.yaml",
            }
        )

    assert not (tmp_path / "appsec-rules").exists()  # noqa: S101
    assert not (tmp_path / ".appsec-tests").exists()  # noqa: S101


def test_validate_helper_returns_parsed_mapping() -> None:
    parsed = mcp_waf._validate_waf_rule_yaml(GOOD_RULE)
    assert parsed["name"] == "mycompany/vpatch-probe"  # noqa: S101


# --- container name conflict -------------------------------------------------

DAEMON_CONFLICT = (
    'docker compose up failed (exit code 1):\nError response from daemon: Conflict. '
    'The container name "/crowdsec-appsec" is already in use by container '
    '"66295a10e290d3cd". You have to remove (or rename) that container to be able to '
    "reuse that name."
)


def test_daemon_container_conflict_is_detected() -> None:
    assert mcp_waf._conflicting_container_names(DAEMON_CONFLICT) == ["crowdsec-appsec"]  # noqa: S101


def test_unrelated_errors_do_not_trigger_removal() -> None:
    """The in-process guard is not a name conflict; remediating it would be wrong."""
    assert mcp_waf._conflicting_container_names("WAF test stack appears to be running already") == []  # noqa: S101
    assert mcp_waf._conflicting_container_names("some other docker failure") == []  # noqa: S101


def test_foreign_container_is_not_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A container we do not own must be reported, never deleted."""
    monkeypatch.setattr(mcp_waf, "_container_compose_project", lambda _name: "someone-elses-project")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: pytest.fail("docker rm must not run for a foreign container"),
    )

    removed, foreign = mcp_waf._remove_own_containers(["crowdsec-appsec"])

    assert removed == []  # noqa: S101
    assert foreign == ["crowdsec-appsec"]  # noqa: S101


# --- rule load verification --------------------------------------------------

RULE = "crowdsecurity/vpatch-CVE-2026-72898"

LOGS_OK = (
    'level=info msg="loading inband rule crowdsecurity/base-config" component=appsec_config\n'
    f'level=info msg="loading inband rule {RULE}" component=appsec_config\n'
    'level=info msg="Loaded 2 inband rules" component=appsec_config'
)


def test_load_check_accepts_a_loaded_rule() -> None:
    assert mcp_waf._analyze_appsec_load_logs(LOGS_OK, RULE) is None  # noqa: S101


def test_load_check_reports_a_rejected_rule() -> None:
    logs = (
        f'level=info msg="loading inband rule {RULE}" component=appsec_config\n'
        f'level=error msg="unable to load inband rule {RULE} : invalid actions for rule"'
    )
    problem = mcp_waf._analyze_appsec_load_logs(logs, RULE)
    assert problem is not None  # noqa: S101
    assert "invalid actions" in problem  # noqa: S101


def test_load_check_reports_a_compile_failure() -> None:
    """Verbatim from a real run: the positive markers appear, then CrowdSec dies.

    Both "loading inband rule" and "Loaded N inband rules" are logged before Coraza
    compiles anything, so they must not be read as proof the rule works.
    """
    logs = (
        'level=info msg="loading inband rule crowdsecurity/base-config" component=appsec_config\n'
        f'level=info msg="loading inband rule {RULE}" component=appsec_config\n'
        'level=info msg="Loaded 2 inband rules" component=appsec_config\n'
        'level=fatal msg="crowdsec init: while loading acquisition config: '
        "datasource of type appsec: unable to initialize runner: unable to initialize inband "
        'engine : invalid WAF config from string: failed to compile the directive \\"secrule\\": '
        'error parsing regexp: invalid or unsupported Perl syntax: `(?P`"'
    )
    problem = mcp_waf._analyze_appsec_load_logs(logs, RULE)
    assert problem is not None  # noqa: S101
    assert "failed to compile the directive" in problem  # noqa: S101


def test_load_check_reports_a_missing_rule() -> None:
    """Rules finished loading, but ours was never among them."""
    logs = (
        'level=info msg="loading inband rule crowdsecurity/base-config" component=appsec_config\n'
        'level=info msg="Loaded 1 inband rules" component=appsec_config'
    )
    problem = mcp_waf._analyze_appsec_load_logs(logs, RULE)
    assert problem is not None  # noqa: S101
    assert RULE in problem  # noqa: S101


def test_load_check_stays_silent_when_logs_are_inconclusive() -> None:
    """Never invent a failure: a false block is worse than the missing signal."""
    assert mcp_waf._analyze_appsec_load_logs("", RULE) is None  # noqa: S101
    assert mcp_waf._analyze_appsec_load_logs("starting crowdsec...", RULE) is None  # noqa: S101
