import json
import re
from pathlib import Path

from .core import SEV, atomic_write_text
from .fingerprints import fingerprinted_findings

BASELINE_VERSION = 1


def build_baseline(repo_id, findings):
    entries = []
    for fingerprint, finding in fingerprinted_findings(findings):
        entries.append({
            "fingerprint": fingerprint,
            "category": finding.category,
            "tool": finding.tool,
            "severity": finding.severity,
            "rule": finding.rule,
            "message": finding.message,
            "file": finding.file.replace("\\", "/"),
            "line": finding.line,
            "commit": finding.commit,
        })
    entries.sort(key=lambda item: item["fingerprint"])
    return {"version": BASELINE_VERSION, "repo_id": repo_id, "findings": entries}


def load_baseline(path, repo_id=None):
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"не удалось прочитать baseline {path}: {error}") from error
    if (not isinstance(data, dict) or type(data.get("version")) is not int
            or data.get("version") != BASELINE_VERSION
            or not isinstance(data.get("repo_id"), str)
            or not data["repo_id"]
            or not isinstance(data.get("findings"), list)):
        raise ValueError(f"неверный формат baseline: {path}")
    if repo_id is not None and data["repo_id"] != repo_id:
        raise ValueError("baseline создан для другого расположения репозитория")
    if any(not isinstance(item, dict) or not isinstance(item.get("fingerprint"), str)
           for item in data["findings"]):
        raise ValueError(f"неверный список находок в baseline: {path}")
    required = ("category", "tool", "severity", "rule", "message", "file", "commit")
    fingerprints = set()
    for item in data["findings"]:
        if (not re.fullmatch(r"[0-9a-f]{64}", item["fingerprint"])
                or any(not isinstance(item.get(key), str) for key in required)
                or item["severity"] not in SEV
                or isinstance(item.get("line"), bool)
                or not isinstance(item.get("line"), int)
                or item["line"] < 0
                or item["fingerprint"] in fingerprints):
            raise ValueError(f"неверная запись находки в baseline: {path}")
        fingerprints.add(item["fingerprint"])
    return data


def baseline_diff(previous, updated):
    old = {item["fingerprint"]: item for item in previous["findings"]} if previous else {}
    new = {item["fingerprint"]: item for item in updated["findings"]}
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    removed = [old[key] for key in sorted(old.keys() - new.keys())]
    return added, removed


def write_baseline(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
