import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bench.bench import _create_work_dir
from codeaudit.cache import cached_stage
from codeaudit.config import load_config
from codeaudit.core import iter_files
from codeaudit.scanners import Finding, _checked_output, tool_ruff
from pipeline import _quality_gate, _repo_identity


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


if __name__ == "__main__":
    unittest.main()
