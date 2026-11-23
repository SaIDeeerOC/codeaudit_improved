#!/usr/bin/env python3
"""Демонстрация конвейера без подготовки: сам создаёт учебный репозиторий
с дефектами (во временном каталоге), запускает pipeline.py и показывает,
где лежат отчёты. Дефекты в демо: секреты разных видов (пароль в коде и в .env,
ключи AWS, токен Slack, JWT, пароль в адресе БД), eval(), SQL-инъекция,
изменяемый аргумент по умолчанию, голый except, curl | sh, коммит «wip».
Запуск:  python3 run_demo.py        (Windows:  py run_demo.py)
"""
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

APP = '''import os
import json

DB_PASSWORD = "Sup3rSecretPass123"   # секрет в коде

SLACK_TOKEN = "xoxb-123456789012-ABCDEFGHIJKLMNopqr"   # токен Slack прямо в коде
TOKEN_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
DATABASE_URL = "postgres://admin:Sup3rSecretPass@db.example.com/prod"   # пароль в адресе


def run(x):
    return eval(x)                   # опасный eval


def query(cur, name):
    cur.execute("SELECT * FROM users WHERE name='" + name + "'")   # SQL-инъекция


def add(item, bucket=[]):            # изменяемый аргумент по умолчанию
    bucket.append(item)
    try:
        return bucket
    except:                          # голый except
        return None
'''

AWS = '''# Учебный пример: ключи должны жить в секрет-менеджере, а не в коде
aws_access_key_id = "AKIAFAKEDEMOKEY12345"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
'''

INSTALL = '#!/bin/sh\ncurl http://example.com/install | sh   # скрипт из сети без проверки\n'


def g(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def main():
    root = Path(tempfile.mkdtemp(prefix="codeaudit_demo_")) / "demo_repo"
    root.mkdir()
    (root / "app.py").write_text(APP, encoding="utf-8")
    (root / "aws.py").write_text(AWS, encoding="utf-8")
    (root / "install.sh").write_text(INSTALL, encoding="utf-8")
    (root / ".env").write_text("AWS_KEY=AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
    g(root, "init", "-q")
    g(root, "add", "-A")
    g(root, "-c", "user.name=Dev", "-c", "user.email=dev@example.com", "commit", "-q", "-m", "wip")
    print(f"Создан учебный репозиторий с дефектами: {root}\n")
    rc = subprocess.run([sys.executable, str(HERE / "pipeline.py"), str(root),
                         "--out", str(HERE / "demo_out"),
                         "--config", str(HERE / "config.toml")]).returncode
    print(f"\nКод возврата: {rc} (1 = quality gate НЕ пройден - так и задумано:")
    print("дефекты в демо-репозитории есть, конвейер должен был их найти и отказать)")
    print(f"HTML-отчёт (открыть в браузере): {HERE / 'demo_out' / 'report.html'}")
    print(f"Текстовый отчёт:                 {HERE / 'demo_out' / 'report.md'}")
    print(f"Машиночитаемый JSON:             {HERE / 'demo_out' / 'report.json'}")


if __name__ == "__main__":
    main()
