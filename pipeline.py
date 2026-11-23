#!/usr/bin/env python3
"""MO-1: локальный (self-hosted) конвейер анализа качества кода и аудита Git.

Стадии: 1) ошибки  2) уязвимости  3) стиль (линтер)  4) секреты  5) история Git.
Внешние open-source инструменты (ruff, bandit, semgrep, gitleaks, shellcheck)
используются, если установлены; встроенные проверки работают без зависимостей
и без сети (только stdlib + git).
Запуск:  python3 pipeline.py /путь/к/репозиторию --out report
Код возврата: 0 - quality gate пройден, 1 - не пройден, 2 - ошибка запуска.
"""
import argparse, ast, hashlib, html, json, re, shutil, subprocess, sys, tempfile, time
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

# На Windows консоль и текстовые файлы по умолчанию в локальной кодировке (cp1251/cp866),
# в которой нет многих символов Unicode (например ≠ из находок). Из-за этого прогон может
# упасть при сохранении отчётов или при печати. Поэтому: все файлы ниже читаются и пишутся
# строго в UTF-8 (encoding="utf-8"), а при выводе в консоль незнакомые символы заменяются,
# а не роняют программу.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

SEV = ["info", "low", "medium", "high", "critical"]
WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 8, "critical": 20}
DEFAULTS = {
    "gate": {"max_high": 0, "min_score": 60},
    "scan": {"exclude_dirs": [".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"],
             "max_file_kb": 1024},
    "git": {"max_files_per_commit": 50, "max_blob_mb": 5, "min_message_len": 10,
            "forbidden_ext": [".exe", ".dll", ".so", ".pem", ".key", ".p12", ".pfx", ".env", ".sqlite", ".zip"],
            "weak_messages": ["wip", "fix", "fixes", "update", "test", "asd", "qwe", "temp", "."]},
    "style": {"max_line_length": 120, "max_complexity": 10, "max_function_lines": 80, "max_args": 7},
    # offline=True: никаких обращений в сеть; semgrep использует только локальные правила
    "tools": {"semgrep_config": "semgrep-rules", "offline": True},
}
SECRET_RE = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical",
     "Ключ доступа AWS (access key id)"),
    ("aws-secret-key", re.compile(r"(?i)aws(?:.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"), "critical",
     "Секретный ключ AWS"),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical",
     "Приватный ключ в коде"),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "critical",
     "Токен GitHub"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "critical",
     "Ключ Google API"),
    ("stripe-api-key", re.compile(r"\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}\b"), "critical",
     "Ключ Stripe (секретный)"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b"), "critical",
     "Токен Slack"),
    ("telegram-bot-token", re.compile(r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b"), "critical",
     "Токен бота Telegram"),
    ("jwt-token", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "high",
     "JWT-токен в коде"),
    ("url-credentials", re.compile(r"\b[a-z][a-z0-9+.\-]{1,30}://[^/\s:@]{1,64}:[^/\s:@]{1,64}@"), "high",
     "Учётные данные в адресе (user:pass@host)"),
    ("hardcoded-credential", re.compile(
        r"""(?i)[a-z0-9_]*(?:password|passwd|secret|api[_-]?key|token)[a-z0-9_]*\s*[:=]\s*['"][^'"\s]{8,}['"]"""), "high",
     "Похоже на пароль/токен, заданный прямо в коде"),
]


@dataclass
class Finding:
    category: str   # error | vulnerability | style | secret | git
    tool: str
    severity: str
    rule: str
    message: str
    file: str = ""
    line: int = 0
    commit: str = ""


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULTS))
    if path and tomllib:
        try:
            with open(path, "rb") as f:
                for sec, vals in tomllib.load(f).items():
                    cfg.setdefault(sec, {}).update(vals)
        except Exception as e:
            print(f"Предупреждение: конфиг {path} не прочитан ({e!r}); "
                  f"используются значения по умолчанию", file=sys.stderr)
    elif path and not tomllib:
        print("Предупреждение: для чтения config.toml нужен Python 3.11+; "
              "используются значения по умолчанию", file=sys.stderr)
    return cfg


def run(cmd, cwd=None, timeout=600, inp=None):
    """Запуск внешней команды. None - инструмент не установлен."""
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
    """Ход работы - в stderr, чтобы stdout оставался машиночитаемым."""
    print(f"  ... {msg}", file=sys.stderr, flush=True)


def iter_files(root, cfg, suffixes=None, skip=None, label=""):
    """Обход файлов проекта. skip - множество путей-строк, которые брать не нужно
    (файлы, переиспользованные из кэша); label - имя этапа для прогресса."""
    ex = set(cfg["scan"]["exclude_dirs"])
    limit = cfg["scan"]["max_file_kb"] * 1024
    n = 0
    for p in root.rglob("*"):
        if not p.is_file() or ex & set(p.relative_to(root).parts):
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


# ---------- Внешние инструменты ----------
def tool_ruff(root, cfg):
    r = run(["ruff", "check", "--output-format", "json", "--select", "E,F,W,B,N,S,C90", "."], cwd=root)
    if r is None:
        return None
    out = []
    for i in json.loads(r[1] or "[]"):
        c = i["code"]
        cat = "vulnerability" if c.startswith("S") else "error" if c[0] in "FB" or c.startswith("E9") else "style"
        sev = "medium" if cat == "vulnerability" else "medium" if cat == "error" else "low"
        out.append(Finding(cat, "ruff", sev, c, i["message"], rel(root, i["filename"]), i["location"]["row"]))
    return out


def tool_bandit(root, cfg):
    r = run(["bandit", "-r", ".", "-f", "json", "-q"], cwd=root)
    if r is None:
        return None
    m = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
    return [Finding("vulnerability", "bandit", m.get(i["issue_severity"], "low"), i["test_id"],
                    i["issue_text"], rel(root, i["filename"]), i["line_number"])
            for i in json.loads(r[1] or "{}").get("results", [])]


def tool_semgrep(root, cfg):
    sc = cfg["tools"]["semgrep_config"]
    if sc == "auto":
        if cfg["tools"].get("offline", True):
            return None  # "auto" качает правила из интернета - запрещено в офлайн-режиме
    else:
        sc = str(Path(sc) if Path(sc).is_absolute() else Path(__file__).resolve().parent / sc)
        if not Path(sc).exists():
            return None
    r = run(["semgrep", "scan", "--config", sc, "--json",
             "--metrics=off", "--disable-version-check", "."], cwd=root, timeout=1800)
    if r is None:
        return None
    m = {"INFO": "low", "WARNING": "medium", "ERROR": "high"}
    return [Finding("vulnerability", "semgrep", m.get(i["extra"].get("severity"), "low"),
                    i["check_id"], i["extra"].get("message", ""), i["path"], i["start"]["line"])
            for i in json.loads(r[1] or "{}").get("results", [])]


def tool_gitleaks(root, cfg):
    with tempfile.TemporaryDirectory() as td:
        rp = Path(td) / "g.json"
        r = run(["gitleaks", "detect", "--source", ".", "--report-format", "json",
                 "--report-path", str(rp), "--no-banner", "--exit-code", "0"], cwd=root)
        if r is None:
            return None
        data = json.loads(rp.read_text(encoding="utf-8") or "[]") if rp.exists() else []
    return [Finding("secret", "gitleaks", "critical", i["RuleID"], i["Description"],
                    i["File"], i["StartLine"], i["Commit"][:10]) for i in data]


def tool_shellcheck(root, cfg):
    files = [str(p) for p in iter_files(root, cfg, {".sh"})]
    if not files:
        return []
    r = run(["shellcheck", "-f", "json"] + files, cwd=root)
    if r is None:
        return None
    m = {"error": "medium", "warning": "low", "info": "info", "style": "info"}
    return [Finding("style", "shellcheck", m.get(i["level"], "low"), f"SC{i['code']}",
                    i["message"], rel(root, i["file"]), i["line"]) for i in json.loads(r[1] or "[]")]


# ---------- Встроенные проверки (без зависимостей) ----------
SRC_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".h", ".cpp", ".cs", ".go", ".php", ".rb", ".sh"}
_JS = {".js", ".ts", ".jsx", ".tsx"}
# Офлайн-правила для не-Python языков: (id, суффиксы или None=все, regex, severity, описание)
PATTERN_RULES = [(i, s, re.compile(r), sev, m) for i, s, r, sev, m in [
    ("js-eval", _JS, r"\beval\s*\(|new\s+Function\s*\(", "high", "eval/Function: выполнение произвольного кода"),
    ("js-innerhtml", _JS, r"\.innerHTML\s*=|document\.write\s*\(", "medium", "Возможный XSS (innerHTML/document.write)"),
    ("js-exec-concat", _JS, r"\bexec(?:Sync)?\s*\([^)]*(?:\+|\$\{)", "high", "Конкатенация в exec - инъекция команд"),
    ("c-unsafe-func", {".c", ".h", ".cpp"}, r"\b(?:gets|strcpy|strcat|sprintf)\s*\(", "high", "Небезопасная функция C (переполнение буфера)"),
    ("c-system", {".c", ".h", ".cpp"}, r"\bsystem\s*\(", "medium", "system(): риск инъекции команд"),
    ("php-eval", {".php"}, r"\beval\s*\(|\bsystem\s*\(\s*\$_(?:GET|POST|REQUEST)", "high", "Выполнение недоверенного кода/команд в PHP"),
    ("php-sqli", {".php"}, r"(?:mysql_query|mysqli_query|->query)\s*\([^)]*\$_(?:GET|POST|REQUEST)", "high", "SQL-инъекция: пользовательский ввод в запросе"),
    ("java-exec", {".java"}, r"Runtime\.getRuntime\(\)\.exec", "medium", "Runtime.exec: риск инъекции команд"),
    ("java-weak-hash", {".java"}, r'MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"', "medium", "Слабый хеш-алгоритм"),
    ("sh-curl-pipe", {".sh"}, r"curl[^|\n]*\|\s*(?:ba)?sh", "high", "Выполнение скрипта из сети без проверки"),
    ("chmod-777", None, r"chmod\s+(?:-R\s+)?777", "medium", "Права 777 на файлы"),
]]


def _dynamic_sql(n):
    if not n.args:
        return False
    a = n.args[0]
    if isinstance(a, ast.JoinedStr):
        return True
    if isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Add, ast.Mod)):
        return not (isinstance(a.left, ast.Constant) and isinstance(a.right, ast.Constant))
    return isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr == "format"


def _is_const(node, value):
    return isinstance(node, ast.Constant) and node.value is value


def builtin_python(root, cfg, skip=None):
    """Синтаксические ошибки и уязвимые конструкции Python (через AST)."""
    out = []
    for p in iter_files(root, cfg, {".py"}, skip=skip, label="builtin-python"):
        f = rel(root, p)
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as e:
            out.append(Finding("error", "builtin", "high", "syntax-error", str(e.msg), f, e.lineno or 0))
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                name = ast.unparse(n.func)
                kws = {k.arg: k.value for k in n.keywords if k.arg}
                v = lambda sev, rule, msg: out.append(Finding("vulnerability", "builtin", sev, rule, msg, f, n.lineno))
                if name in ("eval", "exec"):
                    v("high", "dangerous-eval", f"Вызов {name}() - риск выполнения произвольного кода")
                elif name in ("pickle.loads", "pickle.load", "yaml.load"):
                    v("medium", "unsafe-deserialization", f"{name}() небезопасна для недоверенных данных")
                elif name.startswith("subprocess.") and _is_const(kws.get("shell"), True):
                    v("medium", "shell-true", "subprocess с shell=True - риск инъекции команд")
                if name.endswith((".execute", ".executemany", ".executescript")) and _dynamic_sql(n):
                    v("high", "sql-injection", "SQL-запрос собирается из строк - используйте параметры")
                if name in ("hashlib.md5", "hashlib.sha1"):
                    v("medium", "weak-hash", f"{name}: слабый хеш-алгоритм")
                if _is_const(kws.get("verify"), False):
                    v("medium", "tls-verify-disabled", "Отключена проверка TLS-сертификата")
                if name.endswith(".run") and _is_const(kws.get("debug"), True):
                    v("medium", "debug-enabled", "Включён debug-режим приложения")
                if name == "tempfile.mktemp":
                    v("low", "insecure-tempfile", "tempfile.mktemp подвержена гонке (TOCTOU)")
            elif isinstance(n, ast.ExceptHandler) and n.type is None:
                out.append(Finding("style", "builtin", "low", "bare-except", "Голый except:", f, n.lineno))
    return out


def builtin_python_lint(root, cfg, skip=None):
    """Линтер Python: логические ошибки и стиль (аналог pyflakes/pylint/mccabe)."""
    st, out = cfg["style"], []

    def add(sev, rule, msg, f, line, cat="style"):
        out.append(Finding(cat, "builtin", sev, rule, msg, f, line))

    for p in iter_files(root, cfg, {".py"}, skip=skip, label="builtin-lint"):
        f = rel(root, p)
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in n.targets):
                used |= {e.value for e in getattr(n.value, "elts", []) if isinstance(e, ast.Constant)}
        for n in ast.walk(tree):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                if isinstance(n, ast.ImportFrom) and n.module == "__future__":
                    continue
                for al in n.names:
                    if al.name == "*":
                        add("low", "wildcard-import", "Импорт `*` засоряет пространство имён", f, n.lineno)
                        continue
                    nm = al.asname or al.name.split(".")[0]
                    if nm not in used and p.name != "__init__.py":
                        add("low", "unused-import", f"Неиспользуемый импорт «{nm}»", f, n.lineno)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cx = 1
                for m in ast.walk(n):
                    if isinstance(m, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
                                      ast.IfExp, ast.comprehension)):
                        cx += 1
                    elif isinstance(m, ast.BoolOp):
                        cx += len(m.values) - 1
                if cx > st["max_complexity"]:
                    add("medium", "high-complexity", f"Цикломатическая сложность {cx} > {st['max_complexity']} ({n.name})", f, n.lineno)
                length = (n.end_lineno or n.lineno) - n.lineno + 1
                if length > st["max_function_lines"]:
                    add("low", "long-function", f"Функция {n.name}: {length} строк", f, n.lineno)
                if len(n.args.args) + len(n.args.kwonlyargs) > st["max_args"]:
                    add("low", "too-many-args", f"Слишком много аргументов у {n.name}", f, n.lineno)
                if not re.match(r"^_*[a-z][a-z0-9_]*_*$", n.name) and not (n.name.startswith("__") and n.name.endswith("__")):
                    add("low", "naming-function", f"Имя функции «{n.name}» не в snake_case", f, n.lineno)
                for d in n.args.defaults + [d for d in n.args.kw_defaults if d is not None]:
                    if isinstance(d, (ast.List, ast.Dict, ast.Set)) or (
                            isinstance(d, ast.Call) and ast.unparse(d.func) in ("list", "dict", "set")):
                        add("medium", "mutable-default", "Изменяемое значение аргумента по умолчанию", f, d.lineno, "error")
            elif isinstance(n, ast.ClassDef) and not re.match(r"^_?[A-Z][A-Za-z0-9]*$", n.name):
                add("low", "naming-class", f"Имя класса «{n.name}» не в CapWords", f, n.lineno)
            elif isinstance(n, ast.Assert) and isinstance(n.test, ast.Tuple) and n.test.elts:
                add("medium", "assert-on-tuple", "assert на непустом кортеже всегда истинен", f, n.lineno, "error")
            elif isinstance(n, ast.Compare) and any(isinstance(o, (ast.Eq, ast.NotEq)) for o in n.ops) \
                    and any(_is_const(c, None) for c in n.comparators):
                add("low", "none-comparison", "Сравнение с None через ==; используйте is", f, n.lineno)
            if isinstance(n, (ast.Module, ast.ClassDef)):
                seen = set()
                for s in n.body:
                    if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and not s.decorator_list:
                        if s.name in seen:
                            add("low", "redefined-function", f"Функция «{s.name}» переопределена", f, s.lineno, "error")
                        seen.add(s.name)
    return out


def builtin_patterns(root, cfg, skip=None):
    """Офлайн-правила уязвимостей для JS/TS, C/C++, Java, PHP, shell."""
    out = []
    for p in iter_files(root, cfg, SRC_SUFFIXES, skip=skip, label="builtin-patterns"):
        f = rel(root, p)
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for rid, sufs, rx, sev, msg in PATTERN_RULES:
                if (sufs is None or p.suffix in sufs) and rx.search(line):
                    out.append(Finding("vulnerability", "builtin", sev, rid, msg, f, i))
    return out


def builtin_style(root, cfg, skip=None):
    """Языконезависимый линтер: длина строк, пробелы, EOF, отступы, TODO."""
    st, out = cfg["style"], []
    for p in iter_files(root, cfg, SRC_SUFFIXES, skip=skip, label="builtin-style"):
        f = rel(root, p)
        text = p.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        trailing = [i for i, l in enumerate(lines, 1) if l != l.rstrip()]
        if trailing:
            out.append(Finding("style", "builtin", "info", "trailing-whitespace",
                               f"Пробелы в конце строки ({len(trailing)} шт.)", f, trailing[0]))
        long_n = 0
        for i, l in enumerate(lines, 1):
            if len(l.expandtabs(4)) > st["max_line_length"] and long_n < 50:
                long_n += 1
                out.append(Finding("style", "builtin", "low", "line-too-long",
                                   f"Строка {len(l)} симв. > {st['max_line_length']}", f, i))
            if re.search(r"\b(?:TODO|FIXME|XXX|HACK)\b", l):
                out.append(Finding("style", "builtin", "info", "todo-marker", "Маркер незавершённой работы", f, i))
        if text and not text.endswith("\n"):
            out.append(Finding("style", "builtin", "info", "missing-eof-newline", "Нет перевода строки в конце файла", f, len(lines)))
        if p.suffix == ".py" and {" ", "\t"} <= {l[0] for l in lines if l[:1] in (" ", "\t")}:
            out.append(Finding("style", "builtin", "low", "mixed-indentation", "Смешаны табы и пробелы в отступах", f, 1))
    return out


def scan_text_for_secrets(text, file, line_offset=0, commit="", tool="builtin"):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for rule, rx, sev, msg in SECRET_RE:
            if rx.search(line):
                out.append(Finding("secret", tool, sev, rule, msg,
                                   file, line_offset or i, commit))
    return out


def builtin_secrets(root, cfg, skip=None):
    out = []
    for p in iter_files(root, cfg, skip=skip, label="builtin-secrets"):
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:2048]:
            continue
        out += scan_text_for_secrets(data.decode(errors="replace"), rel(root, p))
    return out


# ---------- Кэш сканирования ----------
# Неизменённые с прошлого прогона файлы не сканируются заново: их результаты
# хранятся в .scan_cache.json в папке отчёта. Кэш сбрасывается при смене
# config.toml или версии формата. Внешние инструменты и аудит истории не кэшируются.
CACHE_VERSION = 2
CACHEABLE = {
    "builtin-python": {".py"},
    "builtin-lint": {".py"},
    "builtin-patterns": SRC_SUFFIXES,
    "builtin-style": SRC_SUFFIXES,
    "builtin-secrets": None,
}


def _file_hash(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _config_fingerprint(config_path):
    try:
        return hashlib.sha256(Path(config_path).read_bytes()).hexdigest()
    except (OSError, TypeError):  # конфиг не задан или не читается - общий ключ
        return "defaults"


def cache_load(outdir, config_path):
    """Кэш прошлого прогона; при отсутствии/устаревании - пустой."""
    fresh = {"version": CACHE_VERSION, "config": _config_fingerprint(config_path),
             "stages": {}, "total": 0}
    p = outdir / ".scan_cache.json"
    if not p.exists():
        return fresh
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return fresh
    if data.get("version") != CACHE_VERSION or data.get("config") != fresh["config"]:
        return fresh
    data.setdefault("stages", {})
    data["total"] = data.get("total", 0)
    return data


def cache_save(outdir, cache):
    try:
        (outdir / ".scan_cache.json").write_text(
            json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def cached_stage(name, fn, root, cfg, cache):
    """Этап с переиспользованием кэша. Возвращает (находки, сколько файлов из кэша)."""
    known = cache["stages"].get(name, {})
    skip, kept, replay = set(), {}, []
    for p in iter_files(root, cfg, CACHEABLE[name]):
        rp = rel(root, p)
        ent = known.get(rp)
        if ent and ent.get("hash") == _file_hash(p):
            skip.add(str(p))
            kept[rp] = ent
            replay += [Finding(**d) for d in ent["findings"]]
    fresh = list(fn(root, cfg, skip=skip))
    byfile = {}
    for f in fresh:
        if f.file:
            byfile.setdefault(f.file, []).append(asdict(f))
    newstage = dict(kept)
    for rp, items in byfile.items():
        try:
            newstage[rp] = {"hash": _file_hash(root / rp), "findings": items}
        except OSError:
            pass
    cache["stages"][name] = newstage
    return fresh + replay, len(skip)


# ---------- Аудит истории Git ----------
def git(root, *args, inp=None):
    r = run(["git", "-C", str(root)] + list(args), inp=inp, timeout=300)
    return None if r is None or r[0] != 0 else r[1]


def git_audit(root, cfg):
    g = cfg["git"]
    out = []
    log = git(root, "log", "--all", "--numstat", "--format=@@%H\x1f%an\x1f%ae\x1f%cn\x1f%at\x1f%G?\x1f%s")
    if log is None:
        return [Finding("git", "git-audit", "info", "no-history", "Нет .git или история пуста")]
    commits, cur = [], None
    for line in log.splitlines():
        if line.startswith("@@"):
            h, an, ae, cn, at, sig, subj = line[2:].split("\x1f", 6)
            cur = {"h": h[:10], "an": an, "ae": ae, "cn": cn, "at": int(at), "sig": sig, "s": subj, "files": []}
            commits.append(cur)
        elif line.strip() and cur is not None:
            parts = line.split("\t")
            if len(parts) == 3:
                cur["files"].append(parts[2])
    now = datetime.now(timezone.utc).timestamp()
    progress(f"git-audit: в истории {len(commits)} коммитов")
    unsigned = 0
    for c in commits:
        s = c["s"].strip()
        if len(s) < g["min_message_len"] or s.lower() in g["weak_messages"]:
            out.append(Finding("git", "git-audit", "low", "weak-message",
                               f"Неинформативное сообщение коммита: «{s}»", commit=c["h"]))
        if len(c["files"]) > g["max_files_per_commit"]:
            out.append(Finding("git", "git-audit", "medium", "huge-commit",
                               f"Коммит затрагивает {len(c['files'])} файлов", commit=c["h"]))
        if c["at"] > now + 86400:
            out.append(Finding("git", "git-audit", "medium", "future-date",
                               "Дата коммита в будущем (подмена времени?)", commit=c["h"]))
        if c["an"] != c["cn"]:
            out.append(Finding("git", "git-audit", "info", "author-committer-differ",
                               f"Автор «{c['an']}» ≠ коммитер «{c['cn']}»", commit=c["h"]))
        if c["sig"] == "N":
            unsigned += 1
        for f in c["files"]:
            if Path(f).suffix.lower() in g["forbidden_ext"] or Path(f).name in (".env", "id_rsa"):
                out.append(Finding("git", "git-audit", "high", "forbidden-file",
                                   "В историю попал потенциально чувствительный/бинарный файл", f, 0, c["h"]))
    if commits and unsigned == len(commits):
        out.append(Finding("git", "git-audit", "info", "unsigned-commits", "Ни один коммит не подписан (GPG/SSH)"))
    emails = {}
    for c in commits:
        emails.setdefault(c["an"], set()).add(c["ae"])
    for n, e in emails.items():
        if len(e) > 2:
            out.append(Finding("git", "git-audit", "low", "many-emails", f"Автор «{n}» использует {len(e)} e-mail"))
    # крупные объекты
    progress("git-audit: оцениваю размеры объектов истории")
    objs = git(root, "rev-list", "--objects", "--all")
    if objs:
        chk = git(root, "cat-file", "--batch-check=%(objecttype) %(objectsize) %(rest)", inp=objs) or ""
        for l in chk.splitlines():
            t = l.split(" ", 2)
            if len(t) >= 2 and t[0] == "blob" and int(t[1]) > g["max_blob_mb"] * 1048576:
                out.append(Finding("git", "git-audit", "medium", "large-blob",
                                   f"Объект {int(t[1]) // 1048576} МБ в истории", t[2] if len(t) > 2 else ""))
    # секреты во ВСЕЙ истории (в т.ч. уже удалённые)
    progress("git-audit: сканирую патчи всей истории на секреты")
    patch = git(root, "log", "--all", "-p", "-U0", "--format=@@%H") or ""
    commit = fname = ""
    lineno = 0  # номер добавляемой строки в самом файле (из hunk-заголовка)
    seen = set()
    commit_re = re.compile(r"^@@([0-9a-f]{40})$")
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    for line in patch.splitlines():
        mc = commit_re.match(line)
        if mc:
            commit = mc.group(1)[:10]
        elif line.startswith("@@ -"):  # заголовок hunk-а: @@ -a,b +c,d @@ - c = строка в новом файле
            mh = hunk_re.match(line)
            lineno = int(mh.group(1)) if mh else 0
        elif line.startswith("+++ b/"):
            fname = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            for f in scan_text_for_secrets(line[1:], fname, line_offset=lineno, commit=commit, tool="git-history"):
                key = (f.rule, fname, commit)
                if key not in seen:
                    seen.add(key)
                    f.message = "Секрет в истории коммитов (даже если удалён из HEAD - считать скомпрометированным)"
                    out.append(f)
            lineno += 1
    return out


# ---------- Отчёты ----------
def score_of(findings):
    return max(0, 100 - sum(WEIGHT[f.severity] for f in findings))


def write_reports(outdir, root, findings, score, gate_ok, notes, history=None, delta=None, elapsed=None):
    outdir.mkdir(parents=True, exist_ok=True)
    fs = sorted(findings, key=lambda f: (-SEV.index(f.severity), f.category, f.file))
    cnt = Counter(f.severity for f in fs)
    cat = Counter(f.category for f in fs)
    summary = {"repo": str(root), "date": datetime.now().isoformat(timespec="seconds"), "score": score,
               "gate_passed": gate_ok, "by_severity": dict(cnt), "by_category": dict(cat), "notes": notes}
    (outdir / "report.json").write_text(json.dumps({"summary": summary, "findings": [asdict(f) for f in fs]},
                                                   ensure_ascii=False, indent=2), encoding="utf-8")
    md = [f"# Отчёт по качеству и аудиту: `{root.name}`", "",
          f"**Оценка:** {score}/100  |  **Quality gate:** {'ПРОЙДЕН' if gate_ok else 'НЕ ПРОЙДЕН'}"
          + (f"  |  Время анализа: {elapsed:.1f} с" if elapsed is not None else ""), "",
          "| Критичность | Кол-во |", "|---|---|"]
    md += [f"| {s} | {cnt.get(s, 0)} |" for s in reversed(SEV)]
    md += ["", "Категории: " + ", ".join(f"{k}: {v}" for k, v in cat.items()), ""]
    md += [f"_{n}_" for n in notes]
    if history:
        md += ["", "## Динамика проверок", ""]
        md.append(f"К прошлому прогону: **{delta:+d}**" if delta is not None
                  else "Первый прогон в этой папке отчётов - сравнивать не с чем.")
        md += ["", "| Дата | Оценка | high+critical | Gate |", "|---|---|---|---|"]
        for e in history:
            sevs = e.get("severities", {})
            hi = int(sevs.get("high", 0)) + int(sevs.get("critical", 0))
            mark = " - текущий" if e.get("current") else ""
            md.append(f"| {e.get('date', '?')}{mark} | {e.get('score', '?')} | {hi} "
                      f"| {'OK' if e.get('gate') else 'FAILED'} |")
    md += ["", "## Находки", "",
           "| Sev | Категория | Инструмент | Правило | Место | Описание |", "|---|---|---|---|---|---|"]
    for f in fs:
        loc = f"{f.file}:{f.line}" if f.file and f.line else f.file or (f"commit {f.commit}" if f.commit else "")
        if f.file and f.commit:
            loc += f" @{f.commit}"
        md.append(f"| {f.severity} | {f.category} | {f.tool} | {f.rule} | {loc} | {f.message.replace('|', '/')} |")
    (outdir / "report.md").write_text("\n".join(md), encoding="utf-8")
    color = {"critical": "#b00020", "high": "#d84315", "medium": "#f9a825", "low": "#558b2f", "info": "#607d8b"}
    rows = "".join(
        f"<tr><td style='color:{color[f.severity]};font-weight:bold'>{f.severity}</td><td>{f.category}</td>"
        f"<td>{f.tool}</td><td>{html.escape(f.rule)}</td>"
        f"<td>{html.escape(f.file)}{':' + str(f.line) if f.line else ''} {html.escape(f.commit)}</td>"
        f"<td>{html.escape(f.message)}</td></tr>" for f in fs)
    hist_html = ""
    if history:
        d_html = (f"<p>К прошлому прогону: <b>{delta:+d}</b></p>" if delta is not None
                  else "<p>Первый прогон в этой папке отчётов - сравнивать не с чем.</p>")
        hrows = "".join(
            f"<tr><td>{html.escape(str(e.get('date', '?')))}{' - текущий' if e.get('current') else ''}</td>"
            f"<td>{e.get('score', '?')}</td>"
            f"<td>{int(e.get('severities', {}).get('high', 0)) + int(e.get('severities', {}).get('critical', 0))}</td>"
            f"<td>{'OK' if e.get('gate') else 'FAILED'}</td></tr>" for e in history)
        hist_html = (f"<h2>Динамика проверок</h2>{d_html}<table>"
                     f"<tr><th>Дата<th>Оценка<th>high+critical<th>Gate</tr>{hrows}</table>")
    (outdir / "report.html").write_text(
        f"<!doctype html><meta charset=utf-8><title>Audit</title><style>body{{font:14px sans-serif;margin:2em}}"
        f"table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:4px 8px}}</style>"
        f"<h1>{html.escape(root.name)}: {score}/100 - gate {'OK' if gate_ok else 'FAILED'}</h1>"
        f"<p>{', '.join(f'{k}: {v}' for k, v in cnt.items())}</p>{hist_html}<table><tr><th>Sev<th>Категория<th>Инструмент"
        f"<th>Правило<th>Место<th>Описание</tr>{rows}</table>", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo")
    ap.add_argument("--out", default="report")
    ap.add_argument("--config")
    ap.add_argument("--no-cache", action="store_true",
                    help="сканировать все файлы заново, не использовать кэш прошлого прогона")
    a = ap.parse_args()
    root = Path(a.repo).resolve()
    if not root.is_dir():
        print("Каталог не найден", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    cfg = load_config(a.config)
    outdir = Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)
    cache = None if a.no_cache else cache_load(outdir, a.config)
    findings, notes = [], []
    stages = [("ruff", tool_ruff), ("bandit", tool_bandit), ("semgrep", tool_semgrep),
              ("gitleaks", tool_gitleaks), ("shellcheck", tool_shellcheck),
              ("builtin-python", builtin_python), ("builtin-lint", builtin_python_lint),
              ("builtin-patterns", builtin_patterns), ("builtin-style", builtin_style),
              ("builtin-secrets", builtin_secrets),
              ("git-audit", git_audit)]
    reused_total = 0
    for name, fn in stages:
        print(f"[..] {name}: работаю...", flush=True)
        try:
            if cache is not None and name in CACHEABLE:
                res, reused = cached_stage(name, fn, root, cfg, cache)
                reused_total += reused
                if reused:
                    notes.append(f"{name}: из кэша переиспользовано файлов: {reused}")
            else:
                res, reused = fn(root, cfg), 0
        except Exception as e:  # стадия не должна ронять весь конвейер
            notes.append(f"{name}: ошибка {e!r}")
            print(f"[!!] {name}: ошибка (подробно в отчёте)", flush=True)
            continue
        if res is None:
            notes.append(f"{name}: не установлен или не настроен - пропущен")
            print(f"[--] {name}: пропущен (не установлен/не настроен)", flush=True)
            continue
        print(f"[ok] {name}: {len(res)}" + (f" (файлов из кэша: {reused})" if reused else ""))
        findings += res
    if cache is not None:
        cache_save(outdir, cache)
    uniq = {(f.tool, f.rule, f.file, f.line, f.commit): f for f in findings}  # дедупликация
    findings = list(uniq.values())
    score = score_of(findings)
    high = sum(1 for f in findings if f.severity in ("high", "critical"))
    gate_ok = high <= cfg["gate"]["max_high"] and score >= cfg["gate"]["min_score"]
    # история проверок: каждая строка - один прогон, отчёт показывает динамику
    cnt = Counter(f.severity for f in findings)
    entry = {"date": datetime.now().isoformat(timespec="seconds"), "repo": root.name,
             "score": score, "gate": gate_ok, "severities": dict(cnt)}
    hist_path = outdir / "history.jsonl"
    prev = []
    if hist_path.exists():
        for line in hist_path.read_text(encoding="utf-8").splitlines():
            try:
                prev.append(json.loads(line))
            except Exception:
                pass
    prev_same = [e for e in prev if e.get("repo") == root.name]
    delta = score - prev_same[-1]["score"] if prev_same else None
    with open(hist_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    elapsed = time.monotonic() - t0
    write_reports(outdir, root, findings, score, gate_ok, notes,
                  history=prev_same[-9:] + [dict(entry, current=True)], delta=delta, elapsed=elapsed)
    print(f"Оценка {score}/100, high+critical={high}, gate={'OK' if gate_ok else 'FAILED'}; отчёты: {a.out}/")
    if delta is not None:
        print(f"Динамика: {prev_same[-1]['score']} -> {score} ({delta:+d} к прошлому прогону)")
    cache_msg = f"; из кэша переиспользовано файлов: {reused_total}" if reused_total else ""
    print(f"Готово за {elapsed:.1f} с{cache_msg}")
    return 0 if gate_ok else 1


if __name__ == "__main__":
    sys.exit(main())
