import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .config import config_fingerprint
from .core import CoverageIssue, Finding, atomic_write_text, iter_files, rel
from .scanners import SRC_SUFFIXES

CACHE_VERSION = 4
CACHEABLE = {
    "builtin-python": {".py"},
    "builtin-lint": {".py"},
    "builtin-patterns": SRC_SUFFIXES,
    "builtin-style": SRC_SUFFIXES,
    "builtin-secrets": None,
}


def _file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scan_fingerprint(config_path):
    digest = hashlib.sha256(config_fingerprint(config_path).encode())
    digest.update(f"{sys.version_info.major}.{sys.version_info.minor}".encode())
    package_dir = Path(__file__).resolve().parent
    sources = [package_dir / name
               for name in ("core.py", "config.py", "cache.py", "scanners.py", "history.py")]
    sources.append(package_dir.parent / "pipeline.py")
    for path in sources:
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(str(path).encode())
    return digest.hexdigest()


def cache_load(outdir, config_path):
    fresh = {"version": CACHE_VERSION, "fingerprint": _scan_fingerprint(config_path),
             "stages": {}, "total": 0}
    path = outdir / ".scan_cache.json"
    if not path.exists():
        return fresh
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fresh
    if not isinstance(data, dict) or data.get("version") != CACHE_VERSION \
            or data.get("fingerprint") != fresh["fingerprint"] \
            or not isinstance(data.get("stages"), dict):
        return fresh
    for entries in data["stages"].values():
        if not isinstance(entries, dict):
            return fresh
        for entry in entries.values():
            if not isinstance(entry, dict) or not isinstance(entry.get("hash"), str) \
                    or not isinstance(entry.get("findings"), list):
                return fresh
            required = {"category", "tool", "severity", "rule", "message", "file", "line", "commit"}
            if any(not isinstance(finding, dict) or not required.issubset(finding)
                   or not all(isinstance(finding[key], str)
                              for key in ("category", "tool", "severity", "rule", "message", "file", "commit"))
                   or isinstance(finding["line"], bool) or not isinstance(finding["line"], int)
                   for finding in entry["findings"]):
                return fresh
    data.setdefault("total", 0)
    return data


def cache_save(outdir, cache):
    atomic_write_text(outdir / ".scan_cache.json", json.dumps(cache, ensure_ascii=False))


def cached_stage(name, fn, root, cfg, cache, coverage=None):
    known = cache["stages"].get(name, {})
    if not isinstance(known, dict):
        known = {}
    skip, unchanged = set(), {}
    paths = []
    for path in iter_files(root, cfg, CACHEABLE[name], coverage=coverage):
        try:
            digest = _file_hash(path)
        except OSError as error:
            if coverage is not None:
                coverage.add_issue(CoverageIssue(rel(root, path), "read-error", str(error), True))
            continue
        paths.append(path)
        rel_path = rel(root, path)
        entry = known.get(rel_path)
        if entry and entry.get("hash") == digest:
            skip.add(str(path))
            unchanged[rel_path] = entry
    fresh = list(fn(root, cfg, skip=skip, coverage=coverage))
    failed_files = ({issue.file for issue in coverage.issues if issue.blocks_gate}
                    if coverage is not None else set())
    findings_by_file = {}
    for finding in fresh:
        if finding.file:
            findings_by_file.setdefault(finding.file, []).append(asdict(finding))
    current_stage = dict(unchanged)
    for path in paths:
        rel_path = rel(root, path)
        if rel_path in unchanged or rel_path in failed_files:
            continue
        try:
            current_stage[rel_path] = {
                "hash": _file_hash(path),
                "findings": findings_by_file.get(rel_path, []),
            }
        except OSError as error:
            if coverage is not None:
                coverage.add_issue(CoverageIssue(rel_path, "read-error", str(error), True))
            continue
    cache["stages"][name] = current_stage
    replayed = [Finding(**finding) for entry in unchanged.values() for finding in entry["findings"]]
    return fresh + replayed, len(skip)
