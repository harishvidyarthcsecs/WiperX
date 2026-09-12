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


class TestWipeReportGenerationErrorIsNonFatal:
    def test_report_write_failure_after_successful_wipe_still_exits_zero(self):
        """CLI-04: a report-generation error must not be reported as "FATAL
        ERROR" and must not hide that the wipe itself succeeded."""
        runner = CliRunner()
        with patch(
            "core.execution_manager.ExecutionManager.execute_wipe",
            return_value=_make_result(success=True),
        ), patch(
            "core.report_generator.ReportGenerator.generate_json_report",
            side_effect=OSError("disk full"),
        ):
            result = runner.invoke(
                cli, ["wipe", "sdb", "--local", "--yes", "--operator", "ci-bot"]
            )
        assert result.exit_code == 0, result.output
        assert "FATAL ERROR" not in result.output
        assert "report generation failed" in result.output
        assert "WIPE COMPLETED SUCCESSFULLY" in result.output

    def test_report_write_failure_after_failed_wipe_exits_nonzero(self):
        runner = CliRunner()
        with patch(
            "core.execution_manager.ExecutionManager.execute_wipe",
            return_value=_make_result(success=False, error="strategy failed"),
        ), patch(
            "core.report_generator.ReportGenerator.generate_json_report",
            side_effect=OSError("disk full"),
        ):
            result = runner.invoke(
                cli, ["wipe", "sdb", "--local", "--yes", "--operator", "ci-bot"]
            )
        assert result.exit_code == 1
        assert "FATAL ERROR" not in result.output
        assert "report generation failed" in result.output


class TestRecoverExitCodes:
    def _run(self, tmp_path, total_recovered):
        runner = CliRunner()
        source = tmp_path / "disk.img"
        source.write_bytes(b"\x00" * 1024)
        out_dir = tmp_path / "case_out"

        fake_result = {
            "case_id": "case-1",
            "summary": {
                "total": total_recovered,
                "by_method": {}, "by_category": {}, "by_validation": {},
                "by_confidence_band": {},
            },
            "manifest_sha256": "deadbeef",
            "signed": True,
            "report_path": str(tmp_path / "report.json"),
            "case_dir": str(out_dir),
        }
        with patch("core.recovery.service.recover", return_value=fake_result):
            result = runner.invoke(
                cli, ["recover", "--source", str(source), "--out", str(out_dir)]
            )
        return result

    def test_zero_files_recovered_exits_nonzero(self, tmp_path):
        """CLI-03: recover previously always exited 0, even with nothing
        recovered - a calling script couldn't tell success from a no-op."""
        result = self._run(tmp_path, total_recovered=0)
        assert result.exit_code == 2
        assert "0 files recovered" in result.output

    def test_nonzero_files_recovered_exits_zero(self, tmp_path):
        result = self._run(tmp_path, total_recovered=3)
        assert result.exit_code == 0


class TestWipeFreeErrorHandling:
    def test_service_exception_exits_cleanly_no_traceback(self, tmp_path):
        """CLI-07: wipe_free must show a clean error, not a raw traceback,
        when the service raises unexpectedly."""
        runner = CliRunner()
        mount = tmp_path
        with patch(
            "core.eraser_file.service.wipe_free_space_only",
            side_effect=RuntimeError("unexpected"),
        ):
            result = runner.invoke(cli, ["wipe-free", str(mount), "--yes"])
        assert result.exit_code == 1
        assert "FATAL" in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)

    def test_wipe_free_mount_option_rejects_nonexistent_path(self, tmp_path):
        """CLI-08: --wipe-free is now a validated click.Path, matching the
        folder positional argument's own validation on the same command."""
        runner = CliRunner()
        folder = tmp_path / "to_erase"
        folder.mkdir()
        result = runner.invoke(
            cli,
            ["erase-folder", str(folder), "--wipe-free", "/definitely/does/not/exist", "--yes"],
        )
        assert result.exit_code != 0
        assert "does not exist" in result.output or "Error" in result.output
