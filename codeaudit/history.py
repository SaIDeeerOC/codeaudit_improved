import re
from datetime import datetime, timezone
from pathlib import Path

from .core import Finding, progress, run
from .scanners import scan_text_for_secrets


def git(root, *args, inp=None):
    result = run(["git", "-C", str(root), *args], inp=inp, timeout=300)
    return None if result is None or result[0] != 0 else result[1]


def git_audit(root, cfg):
    git_cfg = cfg["git"]
    findings = []
    log = git(root, "log", "--all", "--numstat",
              "--format=@@%H\x1f%an\x1f%ae\x1f%cn\x1f%at\x1f%G?\x1f%s")
    if log is None:
        return [Finding("git", "git-audit", "info", "no-history", "Нет .git или история пуста")]
    commits, current = [], None
    for line in log.splitlines():
        if line.startswith("@@"):
            fields = line[2:].split("\x1f", 6)
            if len(fields) != 7:
                continue
            commit_hash, author, email, committer, timestamp, signature, subject = fields
            current = {"h": commit_hash[:10], "an": author, "ae": email, "cn": committer,
                       "at": int(timestamp), "sig": signature, "s": subject, "files": []}
            commits.append(current)
        elif line.strip() and current is not None:
            parts = line.split("\t")
            if len(parts) == 3:
                current["files"].append(parts[2])
    now = datetime.now(timezone.utc).timestamp()
    progress(f"git-audit: в истории {len(commits)} коммитов")
    unsigned = 0
    for commit in commits:
        subject = commit["s"].strip()
        if len(subject) < git_cfg["min_message_len"] or subject.lower() in git_cfg["weak_messages"]:
            findings.append(Finding("git", "git-audit", "low", "weak-message",
                                    f"Неинформативное сообщение коммита: «{subject}»", commit=commit["h"]))
        if len(commit["files"]) > git_cfg["max_files_per_commit"]:
            findings.append(Finding("git", "git-audit", "medium", "huge-commit",
                                    f"Коммит затрагивает {len(commit['files'])} файлов", commit=commit["h"]))
        if commit["at"] > now + 86400:
            findings.append(Finding("git", "git-audit", "medium", "future-date",
                                    "Дата коммита в будущем (подмена времени?)", commit=commit["h"]))
        if commit["an"] != commit["cn"]:
            findings.append(Finding("git", "git-audit", "info", "author-committer-differ",
                                    f"Автор «{commit['an']}» ≠ коммитер «{commit['cn']}»", commit=commit["h"]))
        if commit["sig"] == "N":
            unsigned += 1
        forbidden = {extension.lower() for extension in git_cfg["forbidden_ext"]}
        for filename in commit["files"]:
            if Path(filename).suffix.lower() in forbidden or Path(filename).name in (".env", "id_rsa"):
                findings.append(Finding("git", "git-audit", "high", "forbidden-file",
                                        "В историю попал потенциально чувствительный/бинарный файл",
                                        filename, 0, commit["h"]))
    if commits and unsigned == len(commits):
        findings.append(Finding("git", "git-audit", "info", "unsigned-commits",
                                "Ни один коммит не подписан (GPG/SSH)"))
    emails = {}
    for commit in commits:
        emails.setdefault(commit["an"], set()).add(commit["ae"])
    for author, addresses in emails.items():
        if len(addresses) > 2:
            findings.append(Finding("git", "git-audit", "low", "many-emails",
                                    f"Автор «{author}» использует {len(addresses)} e-mail"))
    progress("git-audit: оцениваю размеры объектов истории")
    objects = git(root, "rev-list", "--objects", "--all")
    if objects:
        checked = git(root, "cat-file", "--batch-check=%(objecttype) %(objectsize) %(rest)", inp=objects) or ""
        for line in checked.splitlines():
            parts = line.split(" ", 2)
            if len(parts) >= 2 and parts[0] == "blob" and int(parts[1]) > git_cfg["max_blob_mb"] * 1048576:
                findings.append(Finding("git", "git-audit", "medium", "large-blob",
                                        f"Объект {int(parts[1]) // 1048576} МБ в истории",
                                        parts[2] if len(parts) > 2 else ""))
    progress("git-audit: сканирую патчи всей истории на секреты")
    patch = git(root, "log", "--all", "-p", "-U0", "--format=@@%H") or ""
    commit_hash = filename = ""
    line_number = 0
    seen = set()
    commit_re = re.compile(r"^@@([0-9a-f]{40})$")
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    for line in patch.splitlines():
        match = commit_re.match(line)
        if match:
            commit_hash = match.group(1)[:10]
        elif line.startswith("@@ -"):
            hunk = hunk_re.match(line)
            line_number = int(hunk.group(1)) if hunk else 0
        elif line.startswith("+++ b/"):
            filename = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            for finding in scan_text_for_secrets(line[1:], filename, line_offset=line_number,
                                                  commit=commit_hash, tool="git-history"):
                key = (finding.rule, filename, commit_hash)
                if key not in seen:
                    seen.add(key)
                    finding.message = ("Секрет в истории коммитов (даже если удалён из HEAD - "
                                       "считать скомпрометированным)")
                    findings.append(finding)
            line_number += 1
    return findings
