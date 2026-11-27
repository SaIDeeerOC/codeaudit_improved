import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bench.owasp import SUPPORTED_RULES, _metrics, evaluate, load_cases, render_report
from codeaudit.core import Finding


class OWASPBenchmarkTests(unittest.TestCase):
    def test_reads_comment_metadata_and_labeled_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "expectedresults-0.1.csv"
            source.write_text(
                "# test name, category, real vulnerability, cwe, Benchmark version: 0.1, 2026-01-9\n"
                "BenchmarkTest00001,codeinj,true,94\n"
                "BenchmarkTest00002,pathtraver,false,22\n",
                encoding="utf-8",
            )
            cases = load_cases(source)
        self.assertEqual([(case.name, case.category, case.vulnerable) for case in cases], [
            ("BenchmarkTest00001", "codeinj", True),
            ("BenchmarkTest00002", "pathtraver", False),
        ])

    def test_rejects_non_testcase_paths_and_invalid_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "expectedresults-0.1.csv"
            source.write_text(
                "# test name, category, real vulnerability, cwe\n"
                "../outside,codeinj,true,94\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "недопустимое имя"):
                load_cases(source)

            source.write_text(
                "# test name, category, real vulnerability, cwe\n"
                "BenchmarkTest00001,codeinj,yes,94\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "ожидалось true/false"):
                load_cases(source)

    def test_scores_only_categories_with_explicit_rule_mappings(self):
        self.assertEqual(set(SUPPORTED_RULES), {"cmdi", "codeinj", "deserialization", "hash", "sqli"})
        self.assertEqual(_metrics(1, 1, 1, 1), {
            "tp": 1, "fp": 1, "fn": 1, "tn": 1,
            "precision": 0.5, "recall": 0.5, "f1": 0.5, "accuracy": 0.5,
        })

    def test_evaluation_excludes_unmapped_categories_and_uses_matching_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            testcode = root / "testcode"
            testcode.mkdir()
            csv_path = root / "expectedresults-0.1.csv"
            csv_path.write_text(
                "# test name, category, real vulnerability, cwe\n"
                "BenchmarkTest00001,codeinj,true,94\n"
                "BenchmarkTest00002,codeinj,false,94\n"
                "BenchmarkTest00003,sqli,true,89\n"
                "BenchmarkTest00004,pathtraver,true,22\n",
                encoding="utf-8",
            )
            for index in range(1, 5):
                (testcode / f"BenchmarkTest{index:05}.py").write_text("pass\n", encoding="utf-8")
            detection = Finding("vulnerability", "builtin", "high", "dangerous-eval", "eval",
                                "BenchmarkTest00001.py", 1)
            with patch("bench.owasp._validate_checkout", return_value=(root, csv_path, testcode)), \
                    patch("bench.owasp.builtin_python", return_value=[detection]), \
                    patch("bench.owasp.builtin_patterns", return_value=[]):
                result = evaluate(root)

        self.assertEqual(result["included"], 3)
        self.assertEqual(result["overall"]["tp"], 1)
        self.assertEqual(result["overall"]["tn"], 1)
        self.assertEqual(result["overall"]["fn"], 1)
        self.assertEqual(result["unsupported_categories"], {"pathtraver": 1})
        report = render_report(result)
        self.assertIn("Оценено тестов: 3 из 4", report)
        self.assertIn("pathtraver: количество тестов — 1", report)


if __name__ == "__main__":
    unittest.main()
