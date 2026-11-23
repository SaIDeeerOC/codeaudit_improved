#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Единая точка входа CodeAudit: меню вместо запоминания команд.

Запуск:  python3 run.py            (Windows: двойной клик по run.bat)
Быстрый способ: перетащить папку репозитория на run.bat — меню пропустится,
репозиторий проверится сразу.

Пункты меню:
  1 - демонстрация: учебный репозиторий с дефектами + прогон конвейера
  2 - проверка своего репозитория (путь вводится здесь или передаётся аргументом)
  3 - просмотр и правка порогов строгости (config.toml)
  4 - справка: где отчёты и что читать дальше

Только стандартная библиотека Python. Работает на Windows, Linux, macOS.
"""
import os
import re
import subprocess
import sys
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ── Консоль: включаем ANSI-цвета на Windows, отключаем их вне терминала ──
if os.name == "nt":
    os.system("")  # активирует обработку ANSI-кодов в Windows 10+


def _supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        return True  # после os.system("") Windows 10 понимает ANSI
    return sys.stdout.isatty()


_COLOR = _supports_color()

C_TITLE = "\033[96m" if _COLOR else ""
C_OK = "\033[92m" if _COLOR else ""
C_WARN = "\033[93m" if _COLOR else ""
C_ERR = "\033[91m" if _COLOR else ""
C_DIM = "\033[90m" if _COLOR else ""
C_END = "\033[0m" if _COLOR else ""


def ok(msg):
    print(f"{C_OK}[ok]{C_END} {msg}")


def warn(msg):
    print(f"{C_WARN}[!]{C_END} {msg}")


def err(msg):
    print(f"{C_ERR}[x]{C_END} {msg}")


def py(*args):
    """Запуск python-файла проекта тем же интерпретатором, живой вывод."""
    return subprocess.run([sys.executable, *[str(a) for a in args]]).returncode


def pause():
    try:
        input(f"\n{C_DIM}Нажмите Enter, чтобы вернуться в меню...{C_END}")
    except EOFError:
        pass


def ask_path(prompt):
    raw = input(prompt).strip().strip('"').strip("'")
    return Path(raw).expanduser()


def find_python_tool():
    return HERE / "pipeline.py", HERE / "config.toml"


# ── Пункт 1: демо ──
def action_demo():
    print()
    rc = py(HERE / "run_demo.py")
    report = HERE / "demo_out" / "report.html"
    if report.exists():
        ans = input(f"\n{C_DIM}Открыть отчёт в браузере? [Y/n]: {C_END}").strip().lower()
        if ans in ("", "y", "yes", "д", "дa"):
            webbrowser.open(report.as_uri())
            ok(f"Открыт: {report}")
    if rc not in (0, 1):
        err(f"Демо завершилось с кодом {rc} — смотри текст выше или раздел «Частые проблемы» в ЗАПУСК.md")
    pause()


# ── Пункт 2: свой репозиторий ──
def action_check(repo=None):
    print()
    pipeline, config = find_python_tool()
    if repo is None:
        print("Проверка своего репозитория. Нужна папка, внутри которой есть .git.")
        print(f"{C_DIM}Подсказка: если репозиторий только на GitHub — сначала")
        print(f"git clone <ссылка>, а не «Download ZIP» (в ZIP нет истории .git).{C_END}\n")
        repo = ask_path("Путь к папке репозитория (или Enter для отмены): ")
        if not str(repo).strip():
            warn("Отменено.")
            pause()
            return
    repo = repo.expanduser()
    if not repo.is_dir():
        err(f"Каталог не найден: {repo}")
        pause()
        return
    if not (repo / ".git").exists():
        warn(f"В папке нет .git — история коммитов проверяться не будет (no-history).")
        ans = input(f"{C_DIM}Продолжить только статический анализ? [Y/n]: {C_END}").strip().lower()
        if ans not in ("", "y", "yes", "д"):
            pause()
            return
    print()
    out = HERE / "report_myrepo"
    rc = py(pipeline, repo, "--out", out, "--config", config)
    print()
    if rc == 0:
        ok(f"quality gate ПРОЙДЕН. Отчёт: {out / 'report.html'}")
    elif rc == 1:
        warn("quality gate НЕ пройден — исправляй находки из отчёта и запускай снова.")
        print(f"    Отчёт: {out / 'report.html'}")
    else:
        err(f"Ошибка запуска (код {rc}). Проверь путь и текст ошибки выше.")
        pause()
        return
    if (out / "report.html").exists():
        ans = input(f"{C_DIM}Открыть отчёт в браузере? [Y/n]: {C_END}").strip().lower()
        if ans in ("", "y", "yes", "д"):
            webbrowser.open((out / "report.html").as_uri())
    pause()


# ── Пункт 3: пороги config.toml ──
EDITABLE = {
    "gate.min_score": "минимальная оценка для gate (0-100)",
    "gate.max_high": "сколько high/critical находок допустимо",
    "git.max_blob_mb": "максимальный размер файла в истории, МБ",
    "style.max_line_length": "максимальная длина строки кода",
}


def _read_config_values(config):
    values = {}
    section = ""
    for line in config.read_text(encoding="utf-8").splitlines():
        sec = re.match(r"\[(\w+)\]", line.strip())
        if sec:
            section = sec.group(1)
            continue
        m = re.match(r"(\w+)\s*=\s*([^#]+)", line)
        if m:
            values[f"{section}.{m.group(1)}"] = m.group(2).strip().strip('"')
    return values


def _set_config_value(config, key, new_raw):
    section, name = key.split(".", 1)
    pattern = re.compile(
        r"^(\s*" + re.escape(name) + r"\s*=\s*)([^#\n]+)(#.*)?$", re.M
    )
    text = config.read_text(encoding="utf-8")
    new_text, n = pattern.subn(
        lambda m: m.group(1) + new_raw + (" " + m.group(3) if m.group(3) else ""), text
    )
    if n:
        config.write_text(new_text, encoding="utf-8")
    return n


def action_config():
    print()
    _, config = find_python_tool()
    if not config.exists():
        err(f"Не найден {config}")
        pause()
        return
    values = _read_config_values(config)
    print(f"Текущие пороги ({config.name}):\n")
    for key in EDITABLE:
        cur = values.get(key, "?")
        print(f"  {key:<24} = {cur:<10}  {C_DIM}— {EDITABLE[key]}{C_END}")
    print(f"\n{C_DIM}Остальные настройки — прямо в файле {config.name} любым текстовым редактором.{C_END}")
    key = input("\nКакой ключ поменять (Enter — ничего): ").strip()
    if not key:
        pause()
        return
    if key not in EDITABLE:
        warn(f"Такой ключ менять через меню нельзя. Доступны: {', '.join(EDITABLE)}")
        pause()
        return
    raw = input(f"Новое значение для {key} (сейчас {values.get(key, '?')}): ").strip()
    try:
        int(raw)
    except ValueError:
        err("Нужно целое число, например: 70")
        pause()
        return
    if _set_config_value(config, key, raw):
        ok(f"{key} = {raw} сохранено в {config.name}")
    else:
        err("Строка не найдена — поправь файл руками.")
    pause()


# ── Пункт 4: справка ──
def action_help():
    print()
    print("Где искать результаты:")
    print(f"  {C_DIM}демо:{C_END}            demo_out/report.html   (создаёт пункт 1)")
    print(f"  {C_DIM}свой репозиторий:{C_END} report_myrepo/report.html (создаёт пункт 2)")
    print("\nДальше по документации:")
    print(f"  {C_DIM}ЗАПУСК.md{C_END}  — пошаговая инструкция и «частые проблемы»")
    print(f"  {C_DIM}README.md{C_END}  — архитектура, стадии, метрики качества")
    print("\nСтарые способы запуска тоже работают:")
    print(f"  {C_DIM}run_demo.bat{C_END}      — только демо, двойной клик")
    print(f"  {C_DIM}check_repo.bat{C_END}    — перетащить папку репозитория на иконку")
    print(f"  {C_DIM}python3 pipeline.py <репозиторий> --out report{C_END} — напрямую")
    pause()


# ── Меню ──
def show_banner():
    ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    git = f"{C_OK}есть{C_END}" if _git_ok() else f"{C_ERR}не найден{C_END}"
    print()
    print(f"{C_TITLE}=" * 58)
    print("  CodeAudit — проверка качества кода и истории Git")
    print("=" * 58 + C_END)
    print(f"  Python: {ver}   Git: {git}   Проект: {HERE}")
    if sys.version_info < (3, 11):
        warn("Python < 3.11: config.toml будет проигнорирован конвейером (значения по умолчанию).")
    print()
    print("  1 — Демонстрация: учебный репозиторий с дефектами")
    print("  2 — Проверить свой репозиторий")
    print("  3 — Посмотреть и поменять пороги (config.toml)")
    print("  4 — Справка: где отчёты и что читать дальше")
    print("  0 — Выход")


def _git_ok():
    try:
        return subprocess.run(["git", "--version"], capture_output=True).returncode == 0
    except OSError:
        return False


def menu():
    while True:
        show_banner()
        try:
            choice = input(f"\n{C_TITLE}Выбери пункт и нажми Enter: {C_END}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "1":
            action_demo()
        elif choice == "2":
            action_check()
        elif choice == "3":
            action_config()
        elif choice == "4":
            action_help()
        elif choice in ("0", "q", "Q", "exit"):
            print("Пока!")
            return 0
        else:
            err("Нет такого пункта. Введи число от 0 до 4.")


def main():
    argv = [a for a in sys.argv[1:] if a.strip()]
    if argv:
        # Аргумент = путь к репозиторию (например, перетащили папку на run.bat)
        action_check(Path(argv[0]))
        return 0
    # Проверка, что проект лежит рядом (защита от запуска внутри zip)
    if not (HERE / "pipeline.py").exists():
        err("Рядом с run.py нет pipeline.py — скорее всего файл запущен внутри архива.")
        err("Распакуй архив ЦЕЛИКОМ (правый клик — «Извлечь всё») и запускай из распакованной папки.")
        pause()
        return 2
    return menu()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nПрервано.")
        sys.exit(130)
