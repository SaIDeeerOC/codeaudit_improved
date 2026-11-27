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
from codeaudit.cache import cached_stage
from codeaudit.config import load_config
from codeaudit.core import Finding, iter_files
from codeaudit.reports import write_reports
from codeaudit.scanners import (_checked_output, builtin_patterns, builtin_python,
                                builtin_secrets, tool_ruff)
from codeaudit.suppressions import SuppressedFinding, apply_suppressions, load_suppressions
from pipeline import _progress_text, _quality_gate, _repo_identity, main as run_pipeline
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

            def scan(root_arg, config_arg, skip=None):
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

            def scan(root_arg, config_arg, skip=None):
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


class SafetyAndIdentityTests(unittest.TestCase):
    def test_quality_gate_fails_when_scan_is_incomplete(self):
        score, high, passed = _quality_gate([], load_config(None), scan_complete=False)
        self.assertEqual((score, high, passed), (100, 0, False))

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
                              "<unsafe>", "app.py", 3)
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
