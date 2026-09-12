"""CLI tests via click.testing.CliRunner.

No real disk is ever touched - ExecutionManager.execute_wipe and
ReportGenerator's report-writing methods are monkeypatched throughout.
"""

from unittest.mock import patch

from click.testing import CliRunner

from cli.wiperx_cli import cli


def _make_result(success=True, error=None):
    from core.execution_manager import WipeResult

    return WipeResult(
        success=success,
        disk_identifier="sdb",
        strategy_name="MockStrategy",
        hostname="localhost",
        os_detected="Linux",
        timestamp="2026-01-01T00:00:00Z",
        error=error,
    )


def _patched_report_generator():
    """Context manager stack: no real report files are written."""
    return (
        patch("core.report_generator.ReportGenerator.generate_json_report",
              return_value="/tmp/report.json"),
        patch("core.report_generator.ReportGenerator.generate_signed_json_report",
              return_value=None),
        patch("core.report_generator.ReportGenerator.generate_pdf_report",
              return_value=None),
    )


class TestWipeYesFlag:
    def test_yes_without_operator_errors_cleanly(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["wipe", "sdb", "--local", "--yes"])
        assert result.exit_code == 2
        assert "--operator is required" in result.output

    def test_yes_with_operator_completes_without_prompting(self):
        runner = CliRunner()
        p1, p2, p3 = _patched_report_generator()
        with patch(
            "core.execution_manager.ExecutionManager.execute_wipe",
            return_value=_make_result(success=True),
        ), p1, p2, p3:
            # No `input=` supplied - if the command tried to prompt, this
            # would raise (CliRunner has no stdin data left to read).
            result = runner.invoke(
                cli, ["wipe", "sdb", "--local", "--yes", "--operator", "ci-bot"]
            )
        assert result.exit_code == 0, result.output
        assert "skipping interactive confirmation prompts" in result.output
        assert "WIPE COMPLETED SUCCESSFULLY" in result.output

    def test_without_yes_still_prompts(self):
        """Sanity check: the interactive path is unchanged when --yes isn't given."""
        runner = CliRunner()
        result = runner.invoke(cli, ["wipe", "sdb", "--local"], input="n\n")
        assert "Are you sure you want to wipe disk" in result.output
        assert "Wipe aborted." in result.output
        assert result.exit_code == 0


class TestGetpassDefaultFallback:
    def test_getuser_failure_falls_back_to_unknown_default(self):
        """CLI-02: a raising getpass.getuser() must not crash the command -
        the prompt should still appear with a safe fallback default."""
        runner = CliRunner()
        p1, p2, p3 = _patched_report_generator()
        with patch(
            "core.execution_manager.ExecutionManager.execute_wipe",
            return_value=_make_result(success=True),
        ), patch("cli.wiperx_cli.getpass.getuser", side_effect=KeyError("no user")), \
                p1, p2, p3:
            result = runner.invoke(
                cli,
                ["wipe", "sdb", "--local"],
                input="y\nsdb\ny\n\n",  # confirm, retype, confirm, accept default operator
            )
        assert result.exit_code == 0, result.output
        assert "Operator name (for report)" in result.output
        assert "unknown" in result.output
