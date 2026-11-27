import json
import shutil
import tempfile
import unittest
from datetime import date
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from bench.bench import _create_work_dir
from codeaudit.baseline import baseline_diff, build_baseline, load_baseline, write_baseline
from codeaudit.cache import cached_stage
from codeaudit.config import load_config
from codeaudit.core import CoverageIssue, Finding, ScanCoverage, atomic_write_text, iter_files
from codeaudit.fingerprints import fingerprinted_findings
from codeaudit.provenance import version_satisfies
from codeaudit.reports import write_reports
from codeaudit.scanners import (_checked_output, builtin_patterns, builtin_python,
                                builtin_secrets, tool_ruff)
from codeaudit.suppressions import SuppressedFinding, apply_suppressions, load_suppressions
from pipeline import (_finding_lifecycle, _finding_records, _progress_text, _quality_gate,
                      _repo_identity, main as run_pipeline)
from run import default_report_dir


class ConfigTests(unittest.TestCase):
    def test_rejects_invalid_values_and_unknown_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text("[gate]\nmin_score = 101\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "min_score"):
                load_config(config)
            config.write_text("[gate]\nmin_socre = 50\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "неизвестные параметры"):
                load_config(config)

    def test_validates_required_tools_and_version_constraints(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text('[tools]\nrequired = ["bandit"]\n[tools.versions]\nbandit = ">=1.2,<2.0"\n',
                              encoding="utf-8")
            self.assertEqual(load_config(config)["tools"]["required"], ["bandit"])
            config.write_text('[tools]\nrequired = ["missing-tool"]\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "tools].required"):
                load_config(config)


class FindingIdentityTests(unittest.TestCase):
    def test_fingerprint_ignores_line_changes_and_normalizes_path_separators(self):
        first = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                        "dynamic execution", "src\\app.py", 10)
        moved_line = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                             "dynamic execution", "src/app.py", 22)
        moved_path = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                             "dynamic execution", "src/renamed.py", 22)
        first_id = fingerprinted_findings([first])[0][0]
        self.assertEqual(first_id, fingerprinted_findings([moved_line])[0][0])
        self.assertNotEqual(first_id, fingerprinted_findings([moved_path])[0][0])

    def test_baseline_diff_and_repository_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            first = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                            "dynamic execution", "app.py", 1)
            second = Finding("style", "builtin", "low", "bare-except", "bare except", "app.py", 3)
            previous = build_baseline("repo-a", [first])
            updated = build_baseline("repo-a", [second])
            write_baseline(path, previous)
            loaded = load_baseline(path, "repo-a")
            added, removed = baseline_diff(loaded, updated)
            self.assertEqual([item["rule"] for item in added], ["bare-except"])
            self.assertEqual([item["rule"] for item in removed], ["dangerous-eval"])
            with self.assertRaisesRegex(ValueError, "другого расположения"):
                load_baseline(path, "repo-b")

    def test_version_constraints_support_ranges(self):
        self.assertTrue(version_satisfies("1.9.4", ">=1.8,<2.0"))
        self.assertFalse(version_satisfies("2.0.0", ">=1.8,<2.0"))
        self.assertFalse(version_satisfies(None, ">=1.0"))

    def test_incomplete_scan_does_not_report_findings_as_resolved(self):
        finding = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                          "dynamic execution", "app.py", 1)
        previous = {"scan_complete": True,
                    "finding_fingerprints": [item["fingerprint"] for item in _finding_records([finding])],
                    "finding_records": _finding_records([finding])}
        changes = _finding_lifecycle([], [previous], scan_complete=False)
        self.assertFalse(changes["available"])
        self.assertEqual(changes["resolved"], [])

    def test_complete_scan_reports_resolved_findings(self):
        finding = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                          "dynamic execution", "app.py", 1)
        records = _finding_records([finding])
        previous = {"scan_complete": True, "finding_fingerprints": [records[0]["fingerprint"]],
                    "finding_records": records}
        changes = _finding_lifecycle([], [previous], scan_complete=True)
        self.assertEqual([item["rule"] for item in changes["resolved"]], ["dangerous-eval"])

    def test_finding_lifecycle_marks_reappeared_findings(self):
        finding = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                          "dynamic execution", "app.py", 1)
        records = _finding_records([finding])
        first = {"scan_complete": True, "finding_fingerprints": [records[0]["fingerprint"]],
                 "finding_records": records}
        clean = {"scan_complete": True, "finding_fingerprints": [], "finding_records": []}
        changes = _finding_lifecycle([finding], [first, clean], scan_complete=True)
        self.assertEqual([item["rule"] for item in changes["reopened"]], ["dangerous-eval"])
        self.assertEqual(changes["new"], [])

    def test_baseline_findings_are_excluded_from_score_and_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            out = Path(directory) / "report"
            root.mkdir()
            (root / "app.py").write_text("eval(input())\n", encoding="utf-8")
            finding = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                              "Вызов eval() - риск выполнения произвольного кода", "app.py", 1)
            baseline_path = Path(directory) / "baseline.json"
            write_baseline(baseline_path, build_baseline(_repo_identity(root), [finding]))
            with patch("pipeline.tool_ruff", return_value=None), \
                    patch("pipeline.tool_bandit", return_value=None), \
                    patch("pipeline.tool_semgrep", return_value=None), \
                    patch("pipeline.tool_gitleaks", return_value=None), \
                    patch("pipeline.tool_shellcheck", return_value=None), \
                    patch("pipeline.collect_tool_versions", return_value=({}, {})), \
                    redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                result = run_pipeline([str(root), "--out", str(out), "--baseline", str(baseline_path)])
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            markdown = (out / "report.md").read_text(encoding="utf-8")
            html_report = (out / "report.html").read_text(encoding="utf-8")
            sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
            self.assertEqual(result, 0)
            self.assertEqual(report["summary"]["score"], 100)
            self.assertEqual(report["summary"]["baseline_count"], 1)
            self.assertEqual(report["baseline_findings"][0]["rule"], "dangerous-eval")
            self.assertIn("provenance", report)
            self.assertIn("Воспроизводимость", markdown)
            self.assertIn("Воспроизводимость", html_report)
            self.assertIn("provenance", sarif["runs"][0]["properties"])

    def test_missing_required_analyzer_marks_scan_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            out = Path(directory) / "report"
            config = Path(directory) / "config.toml"
            root.mkdir()
            (root / "app.py").write_text("pass\n", encoding="utf-8")
            config.write_text('[tools]\nrequired = ["bandit"]\n', encoding="utf-8")
            with patch("pipeline.tool_ruff", return_value=None), \
                    patch("pipeline.tool_bandit", return_value=None), \
                    patch("pipeline.tool_semgrep", return_value=None), \
                    patch("pipeline.tool_gitleaks", return_value=None), \
                    patch("pipeline.tool_shellcheck", return_value=None), \
                    patch("pipeline.collect_tool_versions", return_value=({}, {})), \
                    redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                result = run_pipeline([str(root), "--out", str(out), "--config", str(config)])
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(result, 1)
        self.assertFalse(report["summary"]["scan_complete"])
        self.assertFalse(report["summary"]["gate_passed"])
        self.assertTrue(any("bandit" in note for note in report["summary"]["notes"]))

    def test_baseline_update_requires_complete_scan_and_show_is_local(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            out = Path(directory) / "report"
            baseline_path = Path(directory) / "baseline.json"
            root.mkdir()
            (root / "app.py").write_text("pass\n", encoding="utf-8")
            original = build_baseline(_repo_identity(root), [])
            write_baseline(baseline_path, original)
            with patch("pipeline.tool_ruff", return_value=None), \
                    patch("pipeline.tool_bandit", return_value=None), \
                    patch("pipeline.tool_semgrep", return_value=None), \
                    patch("pipeline.tool_gitleaks", return_value=None), \
                    patch("pipeline.tool_shellcheck", return_value=None), \
                    patch("pipeline.builtin_style", side_effect=RuntimeError("test failure")), \
                    patch("pipeline.collect_tool_versions", return_value=({}, {})), \
                    redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                result = run_pipeline([
                    str(root), "--out", str(out), "--baseline", str(baseline_path), "--update-baseline"
                ])
            shown = StringIO()
            with redirect_stdout(shown):
                show_result = run_pipeline(["--show-baseline", str(baseline_path)])
            persisted = load_baseline(baseline_path, _repo_identity(root))
        self.assertEqual(result, 1)
        self.assertEqual(show_result, 0)
        self.assertIn("Baseline для", shown.getvalue())
        self.assertEqual(persisted, original)

    def test_baseline_diff_requires_confirmation_before_persisting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            out = Path(directory) / "report"
            baseline_path = Path(directory) / "baseline.json"
            root.mkdir()
            (root / "app.py").write_text("pass\n", encoding="utf-8")
            old_finding = Finding("vulnerability", "builtin", "high", "old-rule",
                                  "old issue", "app.py", 1)
            original = build_baseline(_repo_identity(root), [old_finding])
            write_baseline(baseline_path, original)
            output = StringIO()
            with patch("pipeline.tool_ruff", return_value=None), \
                    patch("pipeline.tool_bandit", return_value=None), \
                    patch("pipeline.tool_semgrep", return_value=None), \
                    patch("pipeline.tool_gitleaks", return_value=None), \
                    patch("pipeline.tool_shellcheck", return_value=None), \
                    patch("pipeline.git_audit", return_value=[]), \
                    patch("pipeline.collect_tool_versions", return_value=({}, {})), \
                    patch("builtins.input", return_value="n"), \
                    redirect_stdout(output), redirect_stderr(StringIO()):
                result = run_pipeline([
                    str(root), "--out", str(out), "--baseline", str(baseline_path), "--update-baseline"
                ])
            persisted = load_baseline(baseline_path, _repo_identity(root))
            confirmed_output = StringIO()
            with patch("pipeline.tool_ruff", return_value=None), \
                    patch("pipeline.tool_bandit", return_value=None), \
                    patch("pipeline.tool_semgrep", return_value=None), \
                    patch("pipeline.tool_gitleaks", return_value=None), \
                    patch("pipeline.tool_shellcheck", return_value=None), \
                    patch("pipeline.git_audit", return_value=[]), \
                    patch("pipeline.collect_tool_versions", return_value=({}, {})), \
                    patch("builtins.input", return_value="y"), \
                    redirect_stdout(confirmed_output), redirect_stderr(StringIO()):
                confirm_result = run_pipeline([
                    str(root), "--out", str(out), "--baseline", str(baseline_path), "--update-baseline"
                ])
            approved = load_baseline(baseline_path, _repo_identity(root))
        self.assertEqual(result, 0)
        self.assertIn("Diff baseline: +0 новых, -1 удалённых.", output.getvalue())
        self.assertIn("Baseline не обновлён.", output.getvalue())
        self.assertEqual(persisted, original)
        self.assertEqual(confirm_result, 0)
        self.assertIn("Baseline сохранён:", confirmed_output.getvalue())
        self.assertEqual(approved["findings"], [])


class ScanTests(unittest.TestCase):
    def test_labeled_unsafe_python_examples_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unsafe.py").write_text(
                'def evaluate(value):\n'
                '    return eval(value)\n'
                'def query(cursor, name):\n'
                '    cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n',
                encoding="utf-8")
            rules = {finding.rule for finding in builtin_python(root, load_config(None))}
            self.assertEqual(rules, {"dangerous-eval", "sql-injection"})

    def test_benign_python_near_misses_do_not_create_security_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.py").write_text(
                'import subprocess\n'
                'def query(cursor, name):\n'
                '    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
                'def run_command(arguments):\n'
                '    return subprocess.run(arguments, check=True)\n'
                '# Documentation: avoid dynamic code and unsafe query construction.\n',
                encoding="utf-8")
            cfg = load_config(None)
            self.assertEqual(builtin_python(root, cfg), [])
            self.assertEqual(builtin_patterns(root, cfg), [])
            self.assertEqual(builtin_secrets(root, cfg), [])

    def test_file_iterator_applies_configured_and_output_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "keep.py").write_text("pass\n", encoding="utf-8")
            excluded = root / "vendor"
            excluded.mkdir()
            (excluded / "skip.py").write_text("pass\n", encoding="utf-8")
            output = root / "reports"
            output.mkdir()
            (output / "report.py").write_text("pass\n", encoding="utf-8")
            cfg = load_config(None)
            cfg["scan"]["exclude_dirs"].append("vendor")
            cfg["scan"]["_exclude_paths"] = [str(output)]
            found = {path.relative_to(root).as_posix()
                     for path in iter_files(root, cfg, {".py"})}
            self.assertEqual(found, {"keep.py"})

    def test_file_coverage_reports_size_limit_without_blocking_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "small.py").write_text("pass\n", encoding="utf-8")
            (root / "large.py").write_bytes(b"x" * 1025)
            cfg = load_config(None)
            cfg["scan"]["max_file_kb"] = 1
            coverage = ScanCoverage()

            paths = list(iter_files(root, cfg, {".py"}, coverage=coverage))
            summary = coverage.as_dict()
            score, high, passed = _quality_gate([], cfg, scan_complete=not coverage.has_errors)

        self.assertEqual([path.name for path in paths], ["small.py"])
        self.assertEqual(summary["files_considered"], 2)
        self.assertEqual(summary["size_limited_files"], 1)
        self.assertEqual(summary["errors"], 0)
        self.assertEqual(summary["issues"][0]["reason"], "size-limit")
        self.assertFalse(summary["issues"][0]["blocks_gate"])
        self.assertEqual((score, high, passed), (100, 0, True))

    def test_file_read_error_is_recorded_and_marks_scan_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "unreadable.py"
            source.write_text("pass\n", encoding="utf-8")
            cfg = load_config(None)
            coverage = ScanCoverage()
            original_read_text = Path.read_text

            def read_text(path, *args, **kwargs):
                if path == source:
                    raise PermissionError("access denied")
                return original_read_text(path, *args, **kwargs)

            with patch.object(Path, "read_text", read_text):
                self.assertEqual(builtin_python(root, cfg, coverage=coverage), [])
            score, high, passed = _quality_gate([], cfg, scan_complete=not coverage.has_errors)

        self.assertEqual(coverage.as_dict()["errors"], 1)
        self.assertEqual(coverage.as_dict()["issues"][0]["reason"], "read-error")
        self.assertTrue(coverage.as_dict()["issues"][0]["blocks_gate"])
        self.assertEqual((score, high, passed), (100, 0, False))

    def test_external_scanner_receives_only_eligible_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = root / "good.py"
            good.write_text("pass\n", encoding="utf-8")
            excluded = root / "vendor"
            excluded.mkdir()
            (excluded / "ignored.py").write_text("pass\n", encoding="utf-8")
            (root / "large.py").write_bytes(b"x" * (1024 * 1024 + 1))
            cfg = load_config(None)
            cfg["scan"]["exclude_dirs"].append("vendor")
            calls = []

            def fake_run(command, cwd):
                self.assertEqual(cwd, root)
                calls.append(command)
                return 0, "[]", ""

            with patch("codeaudit.scanners.run", side_effect=fake_run):
                self.assertEqual(tool_ruff(root, cfg), [])
            self.assertEqual(len(calls), 1)
            self.assertIn(str(good), calls[0])
            self.assertNotIn(str(excluded / "ignored.py"), calls[0])
            self.assertNotIn(str(root / "large.py"), calls[0])


class CacheTests(unittest.TestCase):
    def test_clean_files_are_cached_and_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "clean.py"
            source.write_text("pass\n", encoding="utf-8")
            cfg = load_config(None)
            cache = {"stages": {}}
            calls = []

            def scan(root_arg, config_arg, skip=None, coverage=None):
                self.assertEqual(root_arg, root)
                self.assertEqual(config_arg, cfg)
                calls.append(set(skip or ()))
                return []

            findings, reused = cached_stage("builtin-python", scan, root, cfg, cache)
            self.assertEqual((findings, reused), ([], 0))
            entry = cache["stages"]["builtin-python"]["clean.py"]
            self.assertEqual(entry["findings"], [])
            findings, reused = cached_stage("builtin-python", scan, root, cfg, cache)
            self.assertEqual((findings, reused), ([], 1))
            self.assertEqual(len(calls), 2)

    def test_changed_file_replaces_old_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "changed.py"
            source.write_text("bad\n", encoding="utf-8")
            cfg = load_config(None)
            cache = {"stages": {}}

            def scan(root_arg, config_arg, skip=None, coverage=None):
                self.assertEqual(root_arg, root)
                self.assertEqual(config_arg, cfg)
                if str(source) in (skip or set()):
                    return []
                if source.read_text(encoding="utf-8").strip() == "bad":
                    return [Finding("style", "builtin", "low", "bad", "bad", "changed.py", 1)]
                return []

            first, _ = cached_stage("builtin-python", scan, root, cfg, cache)
            self.assertEqual(len(first), 1)
            source.write_text("clean\n", encoding="utf-8")
            second, _ = cached_stage("builtin-python", scan, root, cfg, cache)
            self.assertEqual(second, [])
            self.assertEqual(cache["stages"]["builtin-python"]["changed.py"]["findings"], [])

    def test_scan_errors_are_not_cached_as_clean_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unreadable.py").write_text("pass\n", encoding="utf-8")
            cfg = load_config(None)
            cache = {"stages": {}}
            coverage = ScanCoverage()
            calls = []

            def scan(root_arg, config_arg, skip=None, coverage=None):
                calls.append(True)
                coverage.add_issue(CoverageIssue("unreadable.py", "read-error", "denied", True))
                return []

            for _ in range(2):
                cached_stage("builtin-python", scan, root, cfg, cache, coverage=coverage)
            self.assertEqual(len(calls), 2)
            self.assertEqual(cache["stages"]["builtin-python"], {})


class SafetyAndIdentityTests(unittest.TestCase):
    def test_quality_gate_fails_when_scan_is_incomplete(self):
        score, high, passed = _quality_gate([], load_config(None), scan_complete=False)
        self.assertEqual((score, high, passed), (100, 0, False))

    def test_pipeline_reports_read_errors_and_blocks_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            source = root / "unreadable.py"
            source.write_text("pass\n", encoding="utf-8")
            outdir = Path(directory) / "reports"
            original_read_text = Path.read_text

            def read_text(path, *args, **kwargs):
                if path == source:
                    raise PermissionError("access denied")
                return original_read_text(path, *args, **kwargs)

            with patch.object(Path, "read_text", read_text):
                with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                    result = run_pipeline([str(root), "--out", str(outdir), "--no-cache"])

            report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
            sarif = json.loads((outdir / "report.sarif").read_text(encoding="utf-8"))
        self.assertEqual(result, 1)
        self.assertFalse(report["summary"]["scan_complete"])
        self.assertGreater(report["coverage"]["errors"], 0)
        self.assertFalse(sarif["runs"][0]["invocations"][0]["executionSuccessful"])

    def test_same_directory_names_have_distinct_history_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one" / "repo"
            second = root / "two" / "repo"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            self.assertNotEqual(_repo_identity(first), _repo_identity(second))

    def test_benchmark_uses_a_new_child_without_touching_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            sentinel = parent / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            work = _create_work_dir(parent)
            try:
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
                self.assertTrue(work.is_dir())
                self.assertEqual(work.parent, parent)
            finally:
                shutil.rmtree(work)

    def test_external_tool_failure_is_not_treated_as_clean_output(self):
        with self.assertRaisesRegex(RuntimeError, "кодом 2"):
            _checked_output((2, "[]", "tool error"), "ruff")

    def test_atomic_write_preserves_previous_file_on_replace_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            target.write_text("previous report", encoding="utf-8")
            with patch("codeaudit.core.os.replace", side_effect=OSError("replace failed")):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    atomic_write_text(target, "new report")
            self.assertEqual(target.read_text(encoding="utf-8"), "previous report")
            self.assertEqual(list(Path(directory).glob(".report.json.*.tmp")), [])


class SuppressionTests(unittest.TestCase):
    def test_active_suppression_is_path_and_line_specific(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suppressions.toml"
            path.write_text(
                '[[suppressions]]\nrule = "dangerous-eval"\nfile = "src/app.py"\n'
                'line = 12\nreason = "Confirmed test-only use"\nexpires = 2030-01-01\n',
                encoding="utf-8")
            active, expired = load_suppressions(path, today=date(2029, 1, 1))
            finding = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                              "dynamic execution", r"src\app.py", 12)
            other_line = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                                 "dynamic execution", "src/app.py", 13)
            remaining, suppressed = apply_suppressions([finding, other_line], active)
            self.assertEqual(expired, [])
            self.assertEqual(remaining, [other_line])
            self.assertEqual(len(suppressed), 1)
            self.assertEqual(suppressed[0].reason, "Confirmed test-only use")

    def test_expired_suppression_does_not_hide_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suppressions.toml"
            path.write_text(
                '[[suppressions]]\nrule = "dangerous-eval"\nfile = "app.py"\n'
                'reason = "Temporary exception"\nexpires = 2020-01-01\n',
                encoding="utf-8")
            active, expired = load_suppressions(path, today=date(2021, 1, 1))
            finding = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                              "dynamic execution", "app.py", 1)
            remaining, suppressed = apply_suppressions([finding], active)
            self.assertEqual(len(expired), 1)
            self.assertEqual(remaining, [finding])
            self.assertEqual(suppressed, [])

    def test_rejects_suppression_paths_outside_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suppressions.toml"
            path.write_text(
                '[[suppressions]]\nrule = "rule"\nfile = "../outside.py"\n'
                'reason = "reason"\nexpires = 2030-01-01\n',
                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "относительным путём"):
                load_suppressions(path)

    def test_pipeline_excludes_suppressed_finding_from_gate_but_keeps_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            out = Path(directory) / "report"
            root.mkdir()
            (root / "app.py").write_text(
                "def evaluate(value):\n    return eval(value)\n", encoding="utf-8")
            (root / ".codeaudit-suppressions.toml").write_text(
                '[[suppressions]]\nrule = "dangerous-eval"\nfile = "app.py"\n'
                'reason = "Approved isolated teaching example"\nexpires = 2030-01-01\n',
                encoding="utf-8")
            with patch("pipeline.tool_ruff", return_value=None), \
                    patch("pipeline.tool_bandit", return_value=None), \
                    patch("pipeline.tool_semgrep", return_value=None), \
                    patch("pipeline.tool_gitleaks", return_value=None), \
                    patch("pipeline.tool_shellcheck", return_value=None), \
                    redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                result = run_pipeline([str(root), "--out", str(out)])
            data = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(result, 0)
            self.assertEqual(data["summary"]["score"], 100)
            self.assertFalse(any(finding["rule"] == "dangerous-eval" for finding in data["findings"]))
            self.assertEqual(data["suppressed_findings"][0]["rule"], "dangerous-eval")
            self.assertIn("Approved isolated teaching example",
                          (out / "report.html").read_text(encoding="utf-8"))

    def test_html_report_has_filters_and_json_keeps_suppressed_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "report"
            finding = Finding("vulnerability", "builtin", "high", "dangerous-eval",
                              "<unsafe>", "src/app name.py", 3)
            suppressed = SuppressedFinding(finding, "Reviewed by team", "2030-01-01")
            write_reports(out, Path(directory), [], 100, True, ["Reviewed for release"],
                          suppressed_findings=[suppressed])
            report = (out / "report.html").read_text(encoding="utf-8")
            data = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertIn('id="search"', report)
            self.assertIn('id="severity"', report)
            self.assertIn('id="category"', report)
            self.assertIn('data-sort="0"', report)
            self.assertIn("localeCompare", report)
            self.assertIn("Reviewed for release", report)
            self.assertIn("&lt;unsafe&gt;", report)
            self.assertEqual(data["summary"]["suppressed_count"], 1)
            self.assertEqual(data["suppressed_findings"][0]["suppression_reason"], "Reviewed by team")
            sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["$schema"],
                             "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
                             "sarif-schema-2.1.0.json")
            result = sarif["runs"][0]["results"][0]
            self.assertEqual(result["ruleId"], "builtin/dangerous-eval")
            self.assertEqual(result["level"], "error")
            self.assertEqual(
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "src/app%20name.py")
            self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
            self.assertEqual(result["suppressions"][0]["status"], "accepted")
            self.assertIn("Reviewed by team", result["suppressions"][0]["justification"])
            self.assertTrue(sarif["runs"][0]["invocations"][0]["executionSuccessful"])


class ProgressTests(unittest.TestCase):
    def test_progress_bar_reports_stage_fraction_and_elapsed_seconds(self):
        self.assertIn("[##########----------] 5/10 ( 50%)",
                      _progress_text(5, 10, "git-audit", 3.2))
        self.assertIn("git-audit | 3 с", _progress_text(5, 10, "git-audit", 3.2))


class UsabilityTests(unittest.TestCase):
    def test_same_repository_has_stable_distinct_output_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one" / "repo"
            second = root / "two" / "repo"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            self.assertEqual(default_report_dir(first), default_report_dir(first))
            self.assertNotEqual(default_report_dir(first), default_report_dir(second))


if __name__ == "__main__":
    unittest.main()
