import ast
import json
import re
import tempfile
from pathlib import Path

from .core import Finding, PROJECT_ROOT, iter_files, rel, run

SECRET_RE = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "Ключ доступа AWS (access key id)"),
    ("aws-secret-key", re.compile(r"(?i)aws(?:.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"), "critical", "Секретный ключ AWS"),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical", "Приватный ключ в коде"),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "critical", "Токен GitHub"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "critical", "Ключ Google API"),
    ("stripe-api-key", re.compile(r"\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}\b"), "critical", "Ключ Stripe (секретный)"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b"), "critical", "Токен Slack"),
    ("telegram-bot-token", re.compile(r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b"), "critical", "Токен бота Telegram"),
    ("jwt-token", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "high", "JWT-токен в коде"),
    ("url-credentials", re.compile(r"\b[a-z][a-z0-9+.\-]{1,30}://[^/\s:@]{1,64}:[^/\s:@]{1,64}@"), "high", "Учётные данные в адресе (user:pass@host)"),
    ("hardcoded-credential", re.compile(
        r"""(?i)[a-z0-9_]*(?:password|passwd|secret|api[_-]?key|token)[a-z0-9_]*\s*[:=]\s*['"][^'"\s]{8,}['"]"""),
     "high", "Похоже на пароль/токен, заданный прямо в коде"),
]

SRC_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".h", ".cpp", ".cs", ".go", ".php", ".rb", ".sh"}
JS_SUFFIXES = {".js", ".ts", ".jsx", ".tsx"}
PATTERN_RULES = [(i, s, re.compile(r), sev, m) for i, s, r, sev, m in [
    ("js-eval", JS_SUFFIXES, r"\beval\s*\(|new\s+Function\s*\(", "high", "eval/Function: выполнение произвольного кода"),
    ("js-innerhtml", JS_SUFFIXES, r"\.innerHTML\s*=|document\.write\s*\(", "medium", "Возможный XSS (innerHTML/document.write)"),
    ("js-exec-concat", JS_SUFFIXES, r"\bexec(?:Sync)?\s*\([^)]*(?:\+|\$\{)", "high", "Конкатенация в exec - инъекция команд"),
    ("c-unsafe-func", {".c", ".h", ".cpp"}, r"\b(?:gets|strcpy|strcat|sprintf)\s*\(", "high", "Небезопасная функция C (переполнение буфера)"),
    ("c-system", {".c", ".h", ".cpp"}, r"\bsystem\s*\(", "medium", "system(): риск инъекции команд"),
    ("php-eval", {".php"}, r"\beval\s*\(|\bsystem\s*\(\s*\$_(?:GET|POST|REQUEST)", "high", "Выполнение недоверенного кода/команд в PHP"),
    ("php-sqli", {".php"}, r"(?:mysql_query|mysqli_query|->query)\s*\([^)]*\$_(?:GET|POST|REQUEST)", "high", "SQL-инъекция: пользовательский ввод в запросе"),
    ("java-exec", {".java"}, r"Runtime\.getRuntime\(\)\.exec", "medium", "Runtime.exec: риск инъекции команд"),
    ("java-weak-hash", {".java"}, r'MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"', "medium", "Слабый хеш-алгоритм"),
    ("sh-curl-pipe", {".sh"}, r"curl[^|\n]*\|\s*(?:ba)?sh", "high", "Выполнение скрипта из сети без проверки"),
    ("chmod-777", None, r"chmod\s+(?:-R\s+)?777", "medium", "Права 777 на файлы"),
]]


def _batches(root, cfg, suffixes, size=100):
    batch = []
    for path in iter_files(root, cfg, suffixes):
        batch.append(str(path))
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def _checked_output(result, tool, allowed_codes=(0, 1)):
    if result[0] not in allowed_codes:
        raise RuntimeError(f"{tool} завершился с кодом {result[0]}: {result[2].strip()}")
    return result[1]


def tool_ruff(root, cfg):
    files = list(_batches(root, cfg, {".py"}))
    out = []
    for batch in files:
        r = run(["ruff", "check", "--output-format", "json", "--select", "E,F,W,B,N,S,C90", *batch], cwd=root)
        if r is None:
            return None
        for item in json.loads(_checked_output(r, "ruff") or "[]"):
            code = item["code"]
            category = "vulnerability" if code.startswith("S") else "error" if code[0] in "FB" or code.startswith("E9") else "style"
            severity = "medium" if category in ("vulnerability", "error") else "low"
            out.append(Finding(category, "ruff", severity, code, item["message"],
                               rel(root, item["filename"]), item["location"]["row"]))
    return out


def tool_bandit(root, cfg):
    out = []
    for batch in _batches(root, cfg, {".py"}):
        r = run(["bandit", "-f", "json", "-q", *batch], cwd=root)
        if r is None:
            return None
        m = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
        out.extend(Finding("vulnerability", "bandit", m.get(item["issue_severity"], "low"),
                           item["test_id"], item["issue_text"], rel(root, item["filename"]),
                           item["line_number"])
                   for item in json.loads(_checked_output(r, "bandit") or "{}").get("results", []))
    return out


def tool_semgrep(root, cfg):
    semgrep_config = cfg["tools"]["semgrep_config"]
    if semgrep_config == "auto":
        if cfg["tools"].get("offline", True):
            return None
    else:
        semgrep_config = str(Path(semgrep_config) if Path(semgrep_config).is_absolute()
                             else PROJECT_ROOT / semgrep_config)
        if not Path(semgrep_config).exists():
            return None
    out = []
    for batch in _batches(root, cfg, SRC_SUFFIXES):
        r = run(["semgrep", "scan", "--config", semgrep_config, "--json",
                 "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", *batch],
                cwd=root, timeout=1800)
        if r is None:
            return None
        m = {"INFO": "low", "WARNING": "medium", "ERROR": "high"}
        out.extend(Finding("vulnerability", "semgrep", m.get(item["extra"].get("severity"), "low"),
                           item["check_id"], item["extra"].get("message", ""), item["path"],
                           item["start"]["line"])
                   for item in json.loads(_checked_output(r, "semgrep", (0,)) or "{}").get("results", []))
    return out


def tool_gitleaks(root, cfg):
    with tempfile.TemporaryDirectory() as td:
        report_path = Path(td) / "g.json"
        pathspecs = ["--all", "--", "."]
        excluded = list(cfg["scan"]["exclude_dirs"])
        for path in cfg["scan"].get("_exclude_paths", []):
            try:
                excluded.append(Path(path).resolve().relative_to(root).as_posix())
            except ValueError:
                continue
        for path in excluded:
            normalized = path.strip("/\\")
            if normalized:
                pathspecs.append(f":(exclude){normalized}/**")
        max_megabytes = max(1, cfg["scan"]["max_file_kb"] // 1024)
        r = run(["gitleaks", "git", "--log-opts", " ".join(pathspecs),
                 "--max-target-megabytes", str(max_megabytes), "--report-format", "json",
                 "--report-path", str(report_path), "--no-banner", "--exit-code", "0", str(root)], cwd=root)
        if r is None:
            return None
        _checked_output(r, "gitleaks", (0,))
        data = json.loads(report_path.read_text(encoding="utf-8") or "[]") if report_path.exists() else []
    return [Finding("secret", "gitleaks", "critical", item["RuleID"], item["Description"],
                    item["File"], item["StartLine"], item["Commit"][:10]) for item in data]


def tool_shellcheck(root, cfg):
    files = [str(path) for path in iter_files(root, cfg, {".sh"})]
    if not files:
        return []
    out = []
    for start in range(0, len(files), 100):
        r = run(["shellcheck", "-f", "json", *files[start:start + 100]], cwd=root)
        if r is None:
            return None
        m = {"error": "medium", "warning": "low", "info": "info", "style": "info"}
        out.extend(Finding("style", "shellcheck", m.get(item["level"], "low"),
                           f"SC{item['code']}", item["message"], rel(root, item["file"]), item["line"])
                   for item in json.loads(_checked_output(r, "shellcheck") or "[]"))
    return out


def _dynamic_sql(node):
    if not node.args:
        return False
    arg = node.args[0]
    if isinstance(arg, ast.JoinedStr):
        return True
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
        return not (isinstance(arg.left, ast.Constant) and isinstance(arg.right, ast.Constant))
    return isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format"


def _is_const(node, value):
    return isinstance(node, ast.Constant) and node.value is value


def builtin_python(root, cfg, skip=None):
    out = []
    for path in iter_files(root, cfg, {".py"}, skip=skip, label="builtin-python"):
        filename = rel(root, path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as error:
            out.append(Finding("error", "builtin", "high", "syntax-error", str(error.msg),
                               filename, error.lineno or 0))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                keywords = {key.arg: key.value for key in node.keywords if key.arg}
                def vulnerability(severity, rule, message):
                    out.append(Finding("vulnerability", "builtin", severity, rule, message,
                                       filename, node.lineno))
                if name in ("eval", "exec"):
                    vulnerability("high", "dangerous-eval", f"Вызов {name}() - риск выполнения произвольного кода")
                elif name in ("pickle.loads", "pickle.load", "yaml.load"):
                    vulnerability("medium", "unsafe-deserialization", f"{name}() небезопасна для недоверенных данных")
                if name.startswith("subprocess.") and _is_const(keywords.get("shell"), True):
                    vulnerability("medium", "shell-true", "subprocess с shell=True - риск инъекции команд")
                if name.endswith((".execute", ".executemany", ".executescript")) and _dynamic_sql(node):
                    vulnerability("high", "sql-injection", "SQL-запрос собирается из строк - используйте параметры")
                if name in ("hashlib.md5", "hashlib.sha1"):
                    vulnerability("medium", "weak-hash", f"{name}: слабый хеш-алгоритм")
                if _is_const(keywords.get("verify"), False):
                    vulnerability("medium", "tls-verify-disabled", "Отключена проверка TLS-сертификата")
                if name.endswith(".run") and _is_const(keywords.get("debug"), True):
                    vulnerability("medium", "debug-enabled", "Включён debug-режим приложения")
                if name == "tempfile.mktemp":
                    vulnerability("low", "insecure-tempfile", "tempfile.mktemp подвержена гонке (TOCTOU)")
            elif isinstance(node, ast.ExceptHandler) and node.type is None:
                out.append(Finding("style", "builtin", "low", "bare-except", "Голый except:",
                                   filename, node.lineno))
    return out


def builtin_python_lint(root, cfg, skip=None):
    style, out = cfg["style"], []

    def add(severity, rule, message, filename, line, category="style"):
        out.append(Finding(category, "builtin", severity, rule, message, filename, line))

    for path in iter_files(root, cfg, {".py"}, skip=skip, label="builtin-lint"):
        filename = rel(root, path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        nodes = list(ast.walk(tree))
        used = {node.id for node in nodes if isinstance(node, ast.Name)}
        for node in nodes:
            if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
                used |= {item.value for item in getattr(node.value, "elts", [])
                         if isinstance(item, ast.Constant)}
        for node in nodes:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        add("low", "wildcard-import", "Импорт `*` засоряет пространство имён", filename, node.lineno)
                        continue
                    name = alias.asname or alias.name.split(".")[0]
                    if name not in used and path.name != "__init__.py":
                        add("low", "unused-import", f"Неиспользуемый импорт «{name}»", filename, node.lineno)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = 1
                for child in ast.walk(node):
                    if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
                                          ast.IfExp, ast.comprehension)):
                        complexity += 1
                    elif isinstance(child, ast.BoolOp):
                        complexity += len(child.values) - 1
                if complexity > style["max_complexity"]:
                    add("medium", "high-complexity",
                        f"Цикломатическая сложность {complexity} > {style['max_complexity']} ({node.name})",
                        filename, node.lineno)
                length = (node.end_lineno or node.lineno) - node.lineno + 1
                if length > style["max_function_lines"]:
                    add("low", "long-function", f"Функция {node.name}: {length} строк", filename, node.lineno)
                if len(node.args.args) + len(node.args.kwonlyargs) > style["max_args"]:
                    add("low", "too-many-args", f"Слишком много аргументов у {node.name}", filename, node.lineno)
                if not re.match(r"^_*[a-z][a-z0-9_]*_*$", node.name) and not (
                        node.name.startswith("__") and node.name.endswith("__")):
                    add("low", "naming-function", f"Имя функции «{node.name}» не в snake_case",
                        filename, node.lineno)
                defaults = node.args.defaults + [default for default in node.args.kw_defaults if default is not None]
                for default in defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)) or (
                            isinstance(default, ast.Call) and ast.unparse(default.func) in ("list", "dict", "set")):
                        add("medium", "mutable-default", "Изменяемое значение аргумента по умолчанию",
                            filename, default.lineno, "error")
            elif isinstance(node, ast.ClassDef) and not re.match(r"^_?[A-Z][A-Za-z0-9]*$", node.name):
                add("low", "naming-class", f"Имя класса «{node.name}» не в CapWords", filename, node.lineno)
            elif isinstance(node, ast.Assert) and isinstance(node.test, ast.Tuple) and node.test.elts:
                add("medium", "assert-on-tuple", "assert на непустом кортеже всегда истинен",
                    filename, node.lineno, "error")
            elif isinstance(node, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops) \
                    and any(_is_const(item, None) for item in node.comparators):
                add("low", "none-comparison", "Сравнение с None через ==; используйте is", filename, node.lineno)
            if isinstance(node, (ast.Module, ast.ClassDef)):
                seen = set()
                for statement in node.body:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and not statement.decorator_list:
                        if statement.name in seen:
                            add("low", "redefined-function", f"Функция «{statement.name}» переопределена",
                                filename, statement.lineno, "error")
                        seen.add(statement.name)
    return out


def builtin_patterns(root, cfg, skip=None):
    out = []
    for path in iter_files(root, cfg, SRC_SUFFIXES, skip=skip, label="builtin-patterns"):
        filename = rel(root, path)
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for rule, suffixes, pattern, severity, message in PATTERN_RULES:
                if (suffixes is None or path.suffix in suffixes) and pattern.search(line):
                    out.append(Finding("vulnerability", "builtin", severity, rule, message,
                                       filename, line_number))
    return out


def builtin_style(root, cfg, skip=None):
    style, out = cfg["style"], []
    for path in iter_files(root, cfg, SRC_SUFFIXES, skip=skip, label="builtin-style"):
        filename = rel(root, path)
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        trailing = [index for index, line in enumerate(lines, 1) if line != line.rstrip()]
        if trailing:
            out.append(Finding("style", "builtin", "info", "trailing-whitespace",
                               f"Пробелы в конце строки ({len(trailing)} шт.)", filename, trailing[0]))
        long_count = 0
        for index, line in enumerate(lines, 1):
            if len(line.expandtabs(4)) > style["max_line_length"] and long_count < 50:
                long_count += 1
                out.append(Finding("style", "builtin", "low", "line-too-long",
                                   f"Строка {len(line)} симв. > {style['max_line_length']}", filename, index))
            if re.search(r"\b(?:TODO|FIXME|XXX|HACK)\b", line):
                out.append(Finding("style", "builtin", "info", "todo-marker",
                                   "Маркер незавершённой работы", filename, index))
        if text and not text.endswith("\n"):
            out.append(Finding("style", "builtin", "info", "missing-eof-newline", "Нет перевода строки в конце файла",
                               filename, len(lines)))
        if path.suffix == ".py" and {" ", "\t"} <= {line[0] for line in lines if line[:1] in (" ", "\t")}:
            out.append(Finding("style", "builtin", "low", "mixed-indentation",
                               "Смешаны табы и пробелы в отступах", filename, 1))
    return out


def scan_text_for_secrets(text, filename, line_offset=0, commit="", tool="builtin"):
    out = []
    for index, line in enumerate(text.splitlines(), 1):
        for rule, pattern, severity, message in SECRET_RE:
            if pattern.search(line):
                out.append(Finding("secret", tool, severity, rule, message, filename,
                                   line_offset or index, commit))
    return out


def builtin_secrets(root, cfg, skip=None):
    out = []
    for path in iter_files(root, cfg, skip=skip, label="builtin-secrets"):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:2048]:
            continue
        out.extend(scan_text_for_secrets(data.decode(errors="replace"), rel(root, path)))
    return out
