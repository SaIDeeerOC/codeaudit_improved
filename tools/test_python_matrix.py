#!/usr/bin/env python3
"""Run the project test suite with explicitly selected local Python executables."""
import argparse
import subprocess
import sys
from pathlib import Path


def _interpreter_version(executable, run):
    result = run(
        [executable, "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"Не удалось запустить {executable}.")
    try:
        major, minor = (int(part) for part in result.stdout.strip().split(".", 1))
    except ValueError as error:
        raise RuntimeError(f"Интерпретатор вернул некорректную версию: {result.stdout!r}") from error
    return major, minor


def run_interpreter_tests(executable, root, run=subprocess.run):
    try:
        major, minor = _interpreter_version(executable, run)
    except (OSError, RuntimeError) as error:
        print(f"[!!] {executable}: {error}", file=sys.stderr)
        return 1
    if (major, minor) < (3, 11):
        print(f"[!!] {executable}: Python {major}.{minor}; требуется Python 3.11+.", file=sys.stderr)
        return 1

    print(f"\n=== Проверка на Python {major}.{minor}: {executable} ===", flush=True)
    try:
        result = run(
            [executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=root)
    except OSError as error:
        print(f"[!!] {executable}: {error}", file=sys.stderr)
        return 1
    return result.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python", action="append", dest="interpreters", metavar="EXECUTABLE",
        help="путь к локальному Python 3.11+; параметр можно указать несколько раз")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    interpreters = args.interpreters or [sys.executable]
    failures = 0
    for executable in interpreters:
        failures += run_interpreter_tests(executable, root)
    print(f"\nПроверок не пройдено: {failures} из {len(interpreters)}.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
