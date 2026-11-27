#!/usr/bin/env python3
"""Локальный конвейер анализа качества кода и аудита Git.

Запуск: python3 pipeline.py /путь/к/репозиторию --out report
Код возврата: 0 - quality gate пройден, 1 - gate не пройден или скан неполный,
2 - ошибка запуска.
"""
import argparse
import json
import os
import sys
import threading
import time
from collections import Counter
from pathlib import Path

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

from codeaudit.cache import CACHEABLE, cache_load, cache_save, cached_stage
from codeaudit.config import load_config
from codeaudit.core import ScanCoverage, atomic_write_text
from codeaudit.history import git_audit
from codeaudit.reports import score_of, write_reports
from codeaudit.scanners import (builtin_patterns, builtin_python, builtin_python_lint,
                                builtin_secrets, builtin_style, tool_bandit, tool_gitleaks,
                                tool_ruff, tool_semgrep, tool_shellcheck)
from codeaudit.suppressions import apply_suppressions, load_suppressions


def _repo_identity(root):
    return os.path.normcase(str(root.resolve()))


def _quality_gate(findings, cfg, scan_complete):
    score = score_of(findings)
    high = sum(finding.severity in ("high", "critical") for finding in findings)
    passed = scan_complete and high <= cfg["gate"]["max_high"] and score >= cfg["gate"]["min_score"]
    return score, high, passed


def _progress_text(completed, total, name, elapsed, width=20):
    percent = int(completed * 100 / total) if total else 100
    filled = int(width * completed / total) if total else width
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {completed}/{total} ({percent:3d}%) | {name} | {elapsed:.0f} с"


class _StageProgress:
    def __init__(self, completed, total, name, started):
        self.completed = completed
        self.total = total
        self.name = name
        self.started = started
        self.stop_event = threading.Event()
        self.thread = None
        self.failed = False

    def _render(self):
        elapsed = time.monotonic() - self.started
        print("\r" + _progress_text(self.completed, self.total, self.name, elapsed),
              end="", file=sys.stderr, flush=True)

    def __enter__(self):
        if sys.stderr.isatty():
            self._render()
            self.thread = threading.Thread(target=self._tick, daemon=True)
            self.thread.start()
        return self

    def _tick(self):
        while not self.stop_event.wait(1):
            self._render()

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop_event.set()
        if self.thread:
            self.thread.join()
        elapsed = time.monotonic() - self.started
        text = _progress_text(self.completed + 1, self.total, self.name, elapsed)
        status = " | ошибка" if exc_type or self.failed else " | готово"
        prefix = "\r" if self.thread else ""
        print(prefix + text + status, file=sys.stderr, flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo")
    parser.add_argument("--out", default="report")
    parser.add_argument("--config")
    parser.add_argument("--suppressions",
                        help="TOML-файл исключений; по умолчанию используется .codeaudit-suppressions.toml в репозитории")
    parser.add_argument("--no-cache", action="store_true",
                        help="сканировать все файлы заново, не использовать кэш прошлого прогона")
    args = parser.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print("Каталог не найден", file=sys.stderr)
        return 2
    try:
        cfg = load_config(args.config)
    except ValueError as error:
        print(f"Ошибка конфигурации: {error}", file=sys.stderr)
        return 2
    suppressions_path = (Path(args.suppressions).resolve() if args.suppressions
                         else root / ".codeaudit-suppressions.toml")
    suppressions, expired_suppressions = [], []
    if args.suppressions or suppressions_path.exists():
        try:
            suppressions, expired_suppressions = load_suppressions(suppressions_path)
        except ValueError as error:
            print(f"Ошибка исключений: {error}", file=sys.stderr)
            return 2

    outdir = Path(args.out).resolve()
    if outdir == root:
        print("Папка отчёта не должна совпадать с корнем проверяемого репозитория", file=sys.stderr)
        return 2
    try:
        relative_out = outdir.relative_to(root)
    except ValueError:
        relative_out = None
    if relative_out is not None:
        cfg["scan"]["_exclude_paths"] = [str(outdir)]

    started = time.monotonic()
    outdir.mkdir(parents=True, exist_ok=True)
    cache = None if args.no_cache else cache_load(outdir, args.config)
    findings, notes, failed_stages = [], [], []
    coverage = ScanCoverage()
    stages = [
        ("ruff", tool_ruff, True), ("bandit", tool_bandit, True),
        ("semgrep", tool_semgrep, True), ("gitleaks", tool_gitleaks, False),
        ("shellcheck", tool_shellcheck, True),
        ("builtin-python", builtin_python, True), ("builtin-lint", builtin_python_lint, True),
        ("builtin-patterns", builtin_patterns, True), ("builtin-style", builtin_style, True),
        ("builtin-secrets", builtin_secrets, True), ("git-audit", git_audit, False),
    ]
    reused_total = 0
    for index, (name, function, coverage_aware) in enumerate(stages):
        print(f"[..] {name}: работаю...", flush=True)
        stage_started = time.monotonic()
        stage_failed = False
        with _StageProgress(index, len(stages), name, stage_started) as stage_progress:
            try:
                if cache is not None and name in CACHEABLE:
                    result, reused = cached_stage(name, function, root, cfg, cache, coverage=coverage)
                    reused_total += reused
                    if reused:
                        notes.append(f"{name}: из кэша переиспользовано файлов: {reused}")
                else:
                    result = function(root, cfg, coverage=coverage) if coverage_aware else function(root, cfg)
                    reused = 0
            except Exception as error:
                failed_stages.append(name)
                notes.append(f"{name}: ошибка {error!r}")
                print(f"[!!] {name}: ошибка (подробно в отчёте)", file=sys.stderr, flush=True)
                stage_progress.failed = True
                stage_failed = True
        if stage_failed:
            continue
        if result is None:
            notes.append(f"{name}: не установлен или не настроен - пропущен")
            print(f"[--] {name}: пропущен (не установлен/не настроен)", flush=True)
            continue
        print(f"[ok] {name}: {len(result)}" +
              (f" (файлов из кэша: {reused})" if reused else ""))
        findings.extend(result)

    if cache is not None:
        try:
            cache_save(outdir, cache)
        except OSError as error:
            notes.append(f"Кэш не сохранён: {error!r}")
            print(f"[!!] Кэш не сохранён: {error}", file=sys.stderr, flush=True)

    findings = list({(finding.tool, finding.rule, finding.file, finding.line, finding.commit): finding
                     for finding in findings}.values())
    findings, suppressed_findings = apply_suppressions(findings, suppressions)
    if expired_suppressions:
        notes.append(f"Просроченных исключений: {len(expired_suppressions)}; соответствующие находки учитываются.")
        notes.extend(f"Просрочено исключение: {item.rule} в {item.file}; причина: {item.reason}; срок: {item.expires}"
                     for item in expired_suppressions)
    if suppressed_findings:
        notes.append(f"Исключено по .codeaudit-suppressions.toml: {len(suppressed_findings)} находок.")
    coverage_data = coverage.as_dict()
    if coverage_data["size_limited_files"]:
        notes.append(f"Файлов сверх лимита размера: {coverage_data['size_limited_files']}; см. сведения об охвате.")
    if coverage_data["errors"]:
        notes.append(f"Ошибок доступа к файлам или каталогам: {coverage_data['errors']}; скан неполный.")
    scan_complete = not failed_stages and not coverage.has_errors
    if failed_stages:
        notes.append("Неполный скан: ошибки этапов " + ", ".join(failed_stages))
    score, high, gate_ok = _quality_gate(findings, cfg, scan_complete)

    history_path = outdir / "history.jsonl"
    previous = []
    history_text = history_path.read_text(encoding="utf-8") if history_path.exists() else ""
    for line in history_text.splitlines():
        try:
            previous.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    repo_id = _repo_identity(root)
    previous_same = [entry for entry in previous if entry.get("repo_id") == repo_id]
    entry = {"date": time.strftime("%Y-%m-%dT%H:%M:%S"), "repo": root.name, "repo_id": repo_id,
             "score": score, "gate": gate_ok,
             "severities": dict(Counter(finding.severity for finding in findings)),
             "suppressed": len(suppressed_findings)}
    delta = score - previous_same[-1]["score"] if previous_same else None
    separator = "\n" if history_text and not history_text.endswith("\n") else ""
    atomic_write_text(history_path, history_text + separator + json.dumps(entry, ensure_ascii=False) + "\n")
    elapsed = time.monotonic() - started
    write_reports(outdir, root, findings, score, gate_ok, notes,
                  history=previous_same[-9:] + [dict(entry, current=True)], delta=delta,
                  elapsed=elapsed, scan_complete=scan_complete,
                  suppressed_findings=suppressed_findings, coverage=coverage_data)
    print(f"Оценка {score}/100, high+critical={high}, gate={'OK' if gate_ok else 'FAILED'}; "
          f"отчёты: {args.out}/")
    if not scan_complete:
        print("Сканирование неполное; quality gate считается не пройденным.")
    if delta is not None:
        print(f"Динамика: {previous_same[-1]['score']} -> {score} ({delta:+d} к прошлому прогону)")
    if suppressed_findings:
        print(f"Исключено по причине и сроку: {len(suppressed_findings)} находок (см. отчёт).")
    cache_message = f"; из кэша переиспользовано файлов: {reused_total}" if reused_total else ""
    print(f"Готово за {elapsed:.1f} с{cache_message}")
    return 0 if gate_ok else 1


if __name__ == "__main__":
    sys.exit(main())
