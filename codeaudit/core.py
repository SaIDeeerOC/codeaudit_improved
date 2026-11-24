import shutil
import subprocess
import sys
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


def iter_files(root, cfg, suffixes=None, skip=None, label=""):
    ex = set(cfg["scan"]["exclude_dirs"])
    excluded_paths = [Path(path).resolve() for path in cfg["scan"].get("_exclude_paths", [])]
    limit = cfg["scan"]["max_file_kb"] * 1024
    n = 0
    for p in root.rglob("*"):
        if not p.is_file() or ex & set(p.relative_to(root).parts):
            continue
        resolved = p.resolve()
        if any(resolved == excluded or excluded in resolved.parents for excluded in excluded_paths):
            continue
        if suffixes and p.suffix not in suffixes:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size > limit or (skip and str(p) in skip):
            continue
        n += 1
        if label and n % 5000 == 0:
            progress(f"{label}: просмотрено {n} файлов")
        yield p


def rel(root, p):
    try:
        return str(Path(p).resolve().relative_to(root))
    except ValueError:
        return str(p)
