import hashlib
import json
from collections import defaultdict


def _identity(finding):
    return (
        finding.category,
        finding.tool,
        finding.rule,
        finding.file.replace("\\", "/"),
        finding.commit,
        " ".join(finding.message.split()),
    )


def fingerprinted_findings(findings):
    groups = defaultdict(list)
    for index, finding in enumerate(findings):
        groups[_identity(finding)].append((index, finding))

    fingerprints = [None] * len(findings)
    for identity, occurrences in groups.items():
        for ordinal, (index, _) in enumerate(sorted(
                occurrences, key=lambda item: (item[1].line, item[0]))):
            payload = json.dumps([*identity, ordinal], ensure_ascii=False, separators=(",", ":"))
            fingerprints[index] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return list(zip(fingerprints, findings))
