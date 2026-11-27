import os
import stat
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

SEV = ["info", "low", "medium", "high", "critical"]
WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 8, "critical": 20}
PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Finding:
    category: str
    tool: str
    severity: str
    rule: str
    message: str
    file: str = ""
    line: int = 0
    commit: str = ""


@dataclass(frozen=True)
class CoverageIssue:
    file: str
    reason: str
    detail: str
    blocks_gate: bool
    size_bytes: int | None = None


class ScanCoverage:
    def __init__(self):
        self.files = set()
        self._issues = {}

    def add_file(self, path):
        self.files.add(path)

    def add_issue(self, issue):
        self._issues[(issue.file, issue.reason)] = issue

    @property
    def issues(self):
        return sorted(self._issues.values(), key=lambda issue: (issue.file, issue.reason))

    @property
    def has_errors(self):
        return any(issue.blocks_gate for issue in self._issues.values())

    def as_dict(self):
        issues = [
            {"file": issue.file, "reason": issue.reason, "detail": issue.detail,
             "blocks_gate": issue.blocks_gate, **(
                 {"size_bytes": issue.size_bytes} if issue.size_bytes is not None else {})}
            for issue in self.issues
        ]
        return {
            "files_considered": len(self.files),
            "size_limited_files": sum(not issue.blocks_gate for issue in self._issues.values()),
            "errors": sum(issue.blocks_gate for issue in self._issues.values()),
            "issues": issues,
        }


def run(cmd, cwd=None, timeout=600, inp=None):
    """Run an optional external tool; return None if it is not installed."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                           timeout=timeout, input=inp, errors="replace",
                           stdin=None if inp is not None else subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def progress(msg):
    print(f"  ... {msg}", file=sys.stderr, flush=True)


def atomic_write_text(path, text):
    path = Path(path)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=path.parent,
                prefix=f".{path.name}.", suffix=".tmp", delete=False) as stream:
            temporary_path = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _record_file_error(coverage, root, path, reason, error):
    if coverage is not None:
        coverage.add_issue(CoverageIssue(rel(root, path), reason, str(error), True))


def iter_files(root, cfg, suffixes=None, skip=None, label="", coverage=None):
    root = Path(root)
    ex = set(cfg["scan"]["exclude_dirs"])
    excluded_paths = [Path(path).resolve() for path in cfg["scan"].get("_exclude_paths", [])]
    limit = cfg["scan"]["max_file_kb"] * 1024
    n = 0

    def onerror(error):
        _record_file_error(coverage, root, error.filename or root, "directory-read-error", error)

    def excluded(path):
        if ex & set(path.relative_to(root).parts):
            return True
        try:
            resolved = path.resolve()
        except OSError as error:
            _record_file_error(coverage, root, path, "path-error", error)
            return True
        return any(resolved == excluded_path or excluded_path in resolved.parents
                   for excluded_path in excluded_paths)

    for current, directories, filenames in os.walk(root, topdown=True, onerror=onerror, followlinks=False):
        directory = Path(current)
        directories[:] = [name for name in directories if not excluded(directory / name)]
        for name in filenames:
            path = directory / name
            if excluded(path) or (suffixes and path.suffix not in suffixes):
                continue
            try:
                file_stat = path.stat()
            except OSError as error:
                _record_file_error(coverage, root, path, "stat-error", error)
                continue
            if not stat.S_ISREG(file_stat.st_mode):
                continue
            relative = rel(root, path)
            if coverage is not None:
                coverage.add_file(relative)
            if file_stat.st_size > limit:
                if coverage is not None:
                    coverage.add_issue(CoverageIssue(
                        relative, "size-limit",
                        f"Размер {file_stat.st_size} байт превышает лимит {limit} байт.",
                        False, file_stat.st_size))
                continue
            if skip and str(path) in skip:
                continue
            n += 1
            if label and n % 5000 == 0:
                progress(f"{label}: просмотрено {n} файлов")
            yield path


def rel(root, p):
    try:
        return str(Path(p).resolve().relative_to(root))
    except ValueError:
        return str(p)
