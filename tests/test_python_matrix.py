import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.test_python_matrix import run_interpreter_tests


class LocalPythonMatrixTests(unittest.TestCase):
    def test_runs_tests_with_supported_local_interpreter(self):
        completed = subprocess.CompletedProcess([], 0, "3.13\n", "")
        test_run = subprocess.CompletedProcess([], 0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("tools.test_python_matrix.subprocess.run", side_effect=[completed, test_run]) as run:
                self.assertEqual(run_interpreter_tests("python-test", root, run=run), 0)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0],
                         ["python-test", "-m", "unittest", "discover", "-s", "tests", "-v"])
        self.assertEqual(run.call_args_list[1].kwargs["cwd"], root)

    def test_rejects_unsupported_python_without_running_tests(self):
        version = subprocess.CompletedProcess([], 0, "3.10\n", "")
        with patch("tools.test_python_matrix.subprocess.run", return_value=version) as run:
            self.assertEqual(run_interpreter_tests("python-old", Path("."), run=run), 1)
        self.assertEqual(run.call_count, 1)

    def test_reports_missing_executable_as_failure(self):
        with patch("tools.test_python_matrix.subprocess.run", side_effect=FileNotFoundError("missing")) as run:
            self.assertEqual(run_interpreter_tests("missing-python", Path("."), run=run), 1)


if __name__ == "__main__":
    unittest.main()
