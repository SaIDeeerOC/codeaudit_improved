from dataclasses import dataclass
from datetime import date
import os
from pathlib import Path, PureWindowsPath

from .core import Finding

try:
    import tomllib
except ImportError:
    tomllib = None


@dataclass(frozen=True)
class Suppression:
    rule: str
    file: str
    reason: str
    expires: date
    line: int = 0


@dataclass(frozen=True)
class SuppressedFinding:
    finding: Finding
    reason: str
    expires: str


def _validate_entry(entry, index):
    required = {"rule", "file", "reason", "expires"}
    allowed = required | {"line"}
    if not isinstance(entry, dict) or required - set(entry) or set(entry) - allowed:
        raise ValueError(f"исключение #{index}: нужны rule, file, reason, expires; line — необязателен")
    rule, filename, reason = entry["rule"], entry["file"], entry["reason"]
    if not all(isinstance(value, str) and value.strip() for value in (rule, filename, reason)):
        raise ValueError(f"исключение #{index}: rule, file и reason должны быть непустыми строками")
    return rule, filename, reason


def _validate_filename(filename, index):
    windows_path = PureWindowsPath(filename)
    if Path(filename).is_absolute() or windows_path.is_absolute() or windows_path.drive \
            or ".." in Path(filename.replace("\\", "/")).parts:
        raise ValueError(f"исключение #{index}: file должен быть относительным путём внутри репозитория")
    normalized = filename.replace("\\", "/")
    if not normalized or normalized in (".", "./") or normalized.endswith("/"):
        raise ValueError(f"исключение #{index}: file должен указывать на файл")
    return _normalized_path(filename)


def _parse_expiration(value, index):
    if type(value) is date:
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as error:
            raise ValueError(f"исключение #{index}: expires должен быть датой YYYY-MM-DD") from error
    raise ValueError(f"исключение #{index}: expires должен быть датой YYYY-MM-DD")


def _parse_line(entry, index):
    line = entry.get("line", 0)
    invalid = isinstance(line, bool) or not isinstance(line, int) or line < 0
    if invalid or ("line" in entry and line == 0):
        raise ValueError(f"исключение #{index}: line должен быть положительным целым числом")
    return line


def _parse_entry(entry, index):
    rule, filename, reason = _validate_entry(entry, index)
    filename = _validate_filename(filename, index)
    expires = _parse_expiration(entry["expires"], index)
    line = _parse_line(entry, index)
    return Suppression(rule.strip(), filename, reason.strip(), expires, line)


def _normalized_path(path):
    normalized = str(path).replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.casefold() if os.name == "nt" else normalized


def load_suppressions(path, today=None):
    path = Path(path)
    if not path.exists():
        raise ValueError(f"файл исключений не найден: {path}")
    if tomllib is None:
        raise ValueError("для чтения файла исключений нужен Python 3.11+")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(f"не удалось прочитать файл исключений {path}: {error}") from error
    if not isinstance(data, dict) or set(data) - {"suppressions"}:
        raise ValueError("файл исключений должен содержать только массив [[suppressions]]")
    entries = data.get("suppressions", [])
    if not isinstance(entries, list):
        raise ValueError("[[suppressions]] должен быть массивом таблиц")

    today = today or date.today()
    suppressions, expired = [], []
    for index, entry in enumerate(entries, 1):
        suppression = _parse_entry(entry, index)
        if suppression.expires < today:
            expired.append(suppression)
        else:
            suppressions.append(suppression)
    return suppressions, expired


def apply_suppressions(findings, suppressions):
    active, suppressed = [], []
    for finding in findings:
        filename = _normalized_path(finding.file)
        match = next((item for item in suppressions
                      if item.rule == finding.rule and item.file == filename
                      and (not item.line or item.line == finding.line)), None)
        if match:
            suppressed.append(SuppressedFinding(finding, match.reason, match.expires.isoformat()))
        else:
            active.append(finding)
    return active, suppressed
