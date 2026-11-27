import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from codeaudit.config import load_config
from codeaudit.scanners import (tool_bandit, tool_gitleaks, tool_ruff, tool_semgrep,
                                tool_shellcheck)


def _write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class ExternalToolIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cfg = load_config(None)

    def tearDown(self):
        self.temp.cleanup()

    @unittest.skipUnless(shutil.which("ruff"), "ruff is not installed")
    def test_ruff_finding_is_parsed(self):
        _write(self.root, "unused.py", "import os\n")
        findings = tool_ruff(self.root, self.cfg)
        self.assertTrue(any(f.rule == "F401" for f in findings))

    @unittest.skipUnless(shutil.which("bandit"), "bandit is not installed")
    def test_bandit_finding_is_parsed(self):
        _write(self.root, "unsafe.py", "import subprocess\nsubprocess.run('echo ok', shell=True)\n")
        findings = tool_bandit(self.root, self.cfg)
        self.assertTrue(findings)

    @unittest.skipUnless(shutil.which("semgrep"), "semgrep is not installed")
    def test_semgrep_local_rule_is_parsed(self):
        _write(self.root, "unsafe.py", "def run(value):\n    return eval(value)\n")
        findings = tool_semgrep(self.root, self.cfg)
        self.assertTrue(any(f.rule == "local.python-eval" for f in findings))

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck is not installed")
    def test_shellcheck_finding_is_parsed(self):
        _write(self.root, "unsafe.sh", "#!/bin/sh\necho $1\n")
        findings = tool_shellcheck(self.root, self.cfg)
        self.assertTrue(any(f.rule == "SC2086" for f in findings))

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks is not installed")
    def test_gitleaks_history_finding_is_parsed(self):
        secret = "AKIAABCDEFGHIJKLMNOP"
        _write(self.root, "credentials.py", f"example = {secret!r}\n")
        commands = [
            ["git", "-C", str(self.root), "init", "-q"],
            ["git", "-C", str(self.root), "-c", "user.name=CodeAudit Test",
             "-c", "user.email=test@example.invalid", "add", "-A"],
            ["git", "-C", str(self.root), "-c", "user.name=CodeAudit Test",
             "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "Add test fixture"],
        ]
        for command in commands:
            subprocess.run(command, check=True, capture_output=True)
        findings = tool_gitleaks(self.root, self.cfg)
        self.assertTrue(findings)


if __name__ == "__main__":
    unittest.main()
