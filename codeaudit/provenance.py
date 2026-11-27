import hashlib
import re
import sys
from pathlib import Path

from .config import config_fingerprint
from .core import PROJECT_ROOT, run

VERSION_COMMANDS = {
    "ruff": ["ruff", "--version"],
    "bandit": ["bandit", "--version"],
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "shellcheck": ["shellcheck", "--version"],
}
VERSION_RE = re.compile(r"\d+(?:\.\d+)*")


def collect_tool_versions():
    versions, errors = {}, {}
    for tool, command in VERSION_COMMANDS.items():
        result = run(command, timeout=20)
        if result is None:
            continue
        code, stdout, stderr = result
        match = VERSION_RE.search(stdout + "\n" + stderr)
        if code != 0 or match is None:
            errors[tool] = f"не удалось определить версию (код {code})"
        else:
            versions[tool] = match.group(0)
    return versions, errors


def version_satisfies(version, constraint):
    if not version:
        return False
    actual = tuple(int(part) for part in version.split("."))

    def compare(operator, expected_text):
        expected = tuple(int(part) for part in expected_text.split("."))
        size = max(len(actual), len(expected))
        left = actual + (0,) * (size - len(actual))
        right = expected + (0,) * (size - len(expected))
        return {
            "==": left == right, "!=": left != right, ">=": left >= right,
            "<=": left <= right, ">": left > right, "<": left < right,
            "~=": left >= right and left[0] == right[0]
            and (len(expected) < 3 or left[1] == right[1]),
        }[operator]

    return all(compare(match.group(1), match.group(2).strip())
               for part in constraint.split(",")
               if (match := re.fullmatch(r"\s*(==|!=|>=|<=|>|<|~=)\s*(\d+(?:\.\d+)*)\s*", part)))


def _rules_fingerprint(cfg):
    configured = cfg["tools"]["semgrep_config"]
    if configured == "auto":
        return None
    path = Path(configured)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent.parent / path
    if not path.exists():
        return None
    digest = hashlib.sha256()
    files = [path] if path.is_file() else sorted(item for item in path.rglob("*") if item.is_file())
    for item in files:
        digest.update(item.relative_to(path.parent if path.is_file() else path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(item.read_bytes())
    return digest.hexdigest()


def build_provenance(root, config_path, cfg, tool_versions):
    commit_result = run(["git", "-C", str(root), "rev-parse", "HEAD"], timeout=20)
    branch_result = run(["git", "-C", str(root), "branch", "--show-current"], timeout=20)
    app_revision = run(
        ["git", "-C", str(PROJECT_ROOT), "describe", "--tags", "--always", "--dirty"], timeout=20)
    commit = commit_result[1].strip() if commit_result and commit_result[0] == 0 else None
    branch = branch_result[1].strip() if branch_result and branch_result[0] == 0 else None
    app_version = (app_revision[1].strip()
                   if app_revision and app_revision[0] == 0 and app_revision[1].strip()
                   else "unversioned")
    metadata_errors = []
    try:
        rules_fingerprint = _rules_fingerprint(cfg)
    except OSError as error:
        rules_fingerprint = None
        metadata_errors.append(f"не удалось вычислить fingerprint локальных правил: {error}")
    return {
        "repository_commit": commit,
        "repository_ref": branch or commit,
        "codeaudit_version": app_version,
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "tool_versions": dict(sorted(tool_versions.items())),
        "config_fingerprint": config_fingerprint(config_path),
        "local_rules_fingerprint": rules_fingerprint,
        "metadata_errors": metadata_errors,
    }
