import hashlib
import json
import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    tomllib = None

DEFAULTS = {
    "gate": {"max_high": 0, "min_score": 60},
    "scan": {"exclude_dirs": [".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"],
             "max_file_kb": 1024},
    "git": {"max_files_per_commit": 50, "max_blob_mb": 5, "min_message_len": 10,
            "forbidden_ext": [".exe", ".dll", ".so", ".pem", ".key", ".p12", ".pfx", ".env", ".sqlite", ".zip"],
            "weak_messages": ["wip", "fix", "fixes", "update", "test", "asd", "qwe", "temp", "."]},
    "style": {"max_line_length": 120, "max_complexity": 10, "max_function_lines": 80, "max_args": 7},
    "tools": {"semgrep_config": "semgrep-rules", "offline": True, "required": [], "versions": {}},
}


def _validate_config(cfg):
    expected = {section: set(values) for section, values in DEFAULTS.items()}
    for section, values in cfg.items():
        if section not in expected or not isinstance(values, dict):
            raise ValueError(f"неизвестный раздел или неверный формат: {section}")
        unknown = set(values) - expected[section]
        if unknown:
            raise ValueError(f"неизвестные параметры [{section}]: {', '.join(sorted(unknown))}")

    def integer(section, name, minimum=0, maximum=None):
        value = cfg[section][name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"[{section}].{name} должен быть целым числом")
        if value < minimum or (maximum is not None and value > maximum):
            bounds = f"{minimum}..{maximum}" if maximum is not None else f">= {minimum}"
            raise ValueError(f"[{section}].{name} должен быть в диапазоне {bounds}")

    integer("gate", "max_high")
    integer("gate", "min_score", 0, 100)
    integer("scan", "max_file_kb", 1)
    if not isinstance(cfg["scan"]["exclude_dirs"], list) or not all(
            isinstance(item, str) and item for item in cfg["scan"]["exclude_dirs"]):
        raise ValueError("[scan].exclude_dirs должен быть списком непустых строк")
    integer("git", "max_files_per_commit")
    integer("git", "max_blob_mb", 1)
    integer("git", "min_message_len")
    for name in ("forbidden_ext", "weak_messages"):
        if not isinstance(cfg["git"][name], list) or not all(
                isinstance(item, str) for item in cfg["git"][name]):
            raise ValueError(f"[git].{name} должен быть списком строк")
    for name in ("max_line_length", "max_complexity", "max_function_lines", "max_args"):
        integer("style", name, 1)
    if not isinstance(cfg["tools"]["semgrep_config"], str) or not cfg["tools"]["semgrep_config"]:
        raise ValueError("[tools].semgrep_config должен быть непустой строкой")
    if not isinstance(cfg["tools"]["offline"], bool):
        raise ValueError("[tools].offline должен быть логическим значением")
    tool_names = {"ruff", "bandit", "semgrep", "gitleaks", "shellcheck"}
    required = cfg["tools"]["required"]
    if not isinstance(required, list) or not all(
            isinstance(item, str) and item in tool_names for item in required):
        raise ValueError("[tools].required должен быть списком известных анализаторов")
    versions = cfg["tools"]["versions"]
    if not isinstance(versions, dict):
        raise ValueError("[tools].versions должен быть таблицей версий")
    for name, constraint in versions.items():
        if name not in tool_names or not isinstance(constraint, str) or not constraint:
            raise ValueError("[tools].versions должен содержать диапазоны версий известных анализаторов")
        for part in constraint.split(","):
            if not re.fullmatch(r"\s*(?:==|!=|>=|<=|>|<|~=)\s*\d+(?:\.\d+)*\s*", part):
                raise ValueError(f"неверное ограничение версии для {name}: {constraint}")


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULTS))
    if path and tomllib is None:
        print("Предупреждение: для чтения config.toml нужен Python 3.11+; "
              "используются значения по умолчанию", file=sys.stderr)
        return cfg
    if path:
        try:
            with open(path, "rb") as f:
                user_cfg = tomllib.load(f)
        except (OSError, ValueError) as e:
            raise ValueError(f"не удалось прочитать конфиг {path}: {e}") from e
        if not isinstance(user_cfg, dict):
            raise ValueError("корень TOML-конфига должен быть таблицей")
        for sec, vals in user_cfg.items():
            if sec not in cfg or not isinstance(vals, dict):
                raise ValueError(f"неизвестный раздел или неверный формат: {sec}")
            cfg[sec].update(vals)
    _validate_config(cfg)
    return cfg


def config_fingerprint(config_path):
    digest = hashlib.sha256()
    if config_path:
        try:
            digest.update(Path(config_path).read_bytes())
        except OSError:
            digest.update(b"defaults")
    else:
        digest.update(b"defaults")
    digest.update(Path(__file__).resolve().read_bytes())
    return digest.hexdigest()
