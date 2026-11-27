#!/usr/bin/env python3
"""Evaluate built-in CodeAudit rules on a local OWASP BenchmarkPython checkout."""
import argparse
import csv
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from codeaudit.config import load_config
from codeaudit.scanners import builtin_patterns, builtin_python

BENCHMARK_URL = "https://github.com/OWASP-Benchmark/BenchmarkPython"
BENCHMARK_COMMIT = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
EXPECTED_HEADER = "# test name, category, real vulnerability, cwe"
TEST_NAME = re.compile(r"^BenchmarkTest[0-9]{5,}$")
SUPPORTED_RULES = {
    "cmdi": frozenset({"shell-true"}),
    "codeinj": frozenset({"dangerous-eval"}),
    "deserialization": frozenset({"unsafe-deserialization"}),
    "hash": frozenset({"weak-hash"}),
    "sqli": frozenset({"sql-injection"}),
}


@dataclass(frozen=True)
class TestCase:
    name: str
    category: str
    vulnerable: bool


def load_cases(csv_path):
    with Path(csv_path).open(encoding="utf-8-sig", newline="") as stream:
        metadata = stream.readline().strip()
        if not metadata.lower().startswith(EXPECTED_HEADER):
            raise ValueError("Неизвестный формат expectedresults-0.1.csv.")
        reader = csv.reader(stream)
        cases, seen = [], set()
        for line, row in enumerate(reader, 2):
            if len(row) != 4:
                raise ValueError(f"Строка {line}: ожидалось 4 поля, получено {len(row)}.")
            name, category, vulnerable, _cwe = (item.strip() for item in row)
            if not TEST_NAME.fullmatch(name):
                raise ValueError(f"Строка {line}: недопустимое имя теста {name!r}.")
            if name in seen:
                raise ValueError(f"Строка {line}: повторное имя теста {name!r}.")
            if vulnerable.lower() not in ("true", "false"):
                raise ValueError(f"Строка {line}: ожидалось true/false, получено {vulnerable!r}.")
            seen.add(name)
            cases.append(TestCase(name, category.lower(), vulnerable.lower() == "true"))
    if not cases:
        raise ValueError("Файл разметки не содержит тестовых случаев.")
    return cases


def _validate_checkout(root):
    root = Path(root).resolve()
    csv_path = root / "expectedresults-0.1.csv"
    license_path = root / "LICENSE"
    testcode = root / "testcode"
    if not csv_path.is_file() or not license_path.is_file() or not testcode.is_dir():
        raise ValueError("Ожидается корень локального checkout OWASP BenchmarkPython v0.1.")

    license_text = license_path.read_text(encoding="utf-8", errors="replace")
    if "GNU GENERAL PUBLIC LICENSE" not in license_text or "Version 3" not in license_text[:500]:
        raise ValueError("Лицензия корпуса не соответствует проверенной GNU GPL v3.")

    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, encoding="utf-8",
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("Не удалось определить commit локального корпуса Git.") from error
    if commit != BENCHMARK_COMMIT:
        raise ValueError(
            f"Для воспроизводимости требуется commit {BENCHMARK_COMMIT}; получен {commit or 'пустой'}."
        )

    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all", "--",
         "LICENSE", "expectedresults-0.1.csv", "testcode"],
        capture_output=True, text=True, encoding="utf-8",
    )
    if status.returncode:
        raise ValueError(f"Не удалось проверить состояние корпуса: {status.stderr.strip()}")
    if status.stdout.strip():
        raise ValueError("Файлы корпуса изменены или неотслеживаются; требуется чистый checkout.")
    return root, csv_path, testcode


def _metrics(tp, fp, fn, tn):
    def ratio(numerator, denominator):
        return numerator / denominator if denominator else 0.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": ratio(2 * precision * recall, precision + recall),
        "accuracy": ratio(tp + tn, tp + fp + fn + tn),
    }


def evaluate(root):
    root, csv_path, testcode = _validate_checkout(root)
    cases = load_cases(csv_path)
    missing = []
    for case in cases:
        source = (testcode / f"{case.name}.py").resolve()
        try:
            source.relative_to(testcode.resolve())
        except ValueError as error:
            raise ValueError(f"Путь теста выходит за пределы testcode: {case.name!r}.") from error
        if not source.is_file():
            missing.append(case.name)
    if missing:
        raise ValueError(f"Отсутствуют исходники для {len(missing)} размеченных тестов: {missing[:5]}")

    cfg = load_config(None)
    findings = builtin_python(testcode, cfg) + builtin_patterns(testcode, cfg)
    found_by_file = defaultdict(set)
    for finding in findings:
        if finding.category == "vulnerability":
            found_by_file[Path(finding.file).name].add(finding.rule)

    counts = defaultdict(Counter)
    totals = Counter()
    for case in cases:
        rules = SUPPORTED_RULES.get(case.category)
        if rules is None:
            continue
        detected = bool(found_by_file[case.name + ".py"] & rules)
        totals["included"] += 1
        counts[case.category]["tp" if detected and case.vulnerable else
                             "fp" if detected else
                             "fn" if case.vulnerable else "tn"] += 1

    if not totals["included"]:
        raise ValueError("Ни одна категория с поддерживаемыми правилами CodeAudit не найдена.")
    category_metrics = {
        category: _metrics(row["tp"], row["fp"], row["fn"], row["tn"])
        for category, row in sorted(counts.items())
    }
    overall_counts = Counter()
    for row in counts.values():
        overall_counts.update(row)
    overall = _metrics(*(overall_counts[key] for key in ("tp", "fp", "fn", "tn")))
    return {
        "root": root,
        "cases": cases,
        "category_metrics": category_metrics,
        "overall": overall,
        "included": totals["included"],
        "unsupported_categories": Counter(case.category for case in cases
                                           if case.category not in SUPPORTED_RULES),
        "rules": SUPPORTED_RULES,
    }


def render_report(result):
    categories = Counter(case.category for case in result["cases"])
    lines = [
        "# Независимая оценка по OWASP BenchmarkPython",
        "",
        f"- Источник: {BENCHMARK_URL}",
        f"- Commit: `{BENCHMARK_COMMIT}`",
        "- Лицензия корпуса: GNU GPL v3; используется локальный checkout пользователя.",
        "- Область анализа: встроенные Python- и pattern-правила CodeAudit; внешние анализаторы не включены.",
        f"- Оценено тестов: {result['included']} из {len(result['cases'])} "
        f"({result['included'] / len(result['cases']):.1%} покрытия по поддерживаемым категориям)",
        "",
        "Оценка включает только категории с сопоставленными правилами CodeAudit. Она не является "
        "официальным результатом OWASP Benchmark и не характеризует исключённые категории.",
        "",
        "| Категория | Тестов | Правила | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for category, metric in result["category_metrics"].items():
        rules = ", ".join(sorted(result["rules"][category]))
        lines.append(
            f"| {category} | {categories[category]} | {rules} | {metric['tp']} | {metric['fp']} | "
            f"{metric['fn']} | {metric['tn']} | {metric['precision']:.3f} | {metric['recall']:.3f} | "
            f"{metric['f1']:.3f} | {metric['accuracy']:.3f} |"
        )
    metric = result["overall"]
    lines.extend([
        f"| **Итого (micro)** | **{result['included']}** | — | **{metric['tp']}** | **{metric['fp']}** | "
        f"**{metric['fn']}** | **{metric['tn']}** | **{metric['precision']:.3f}** | "
        f"**{metric['recall']:.3f}** | **{metric['f1']:.3f}** | **{metric['accuracy']:.3f}** |",
        "",
        "## Исключённые категории",
        "",
    ])
    lines.extend(f"- {category}: количество тестов — {count} (нет сопоставленного правила CodeAudit)"
                 for category, count in sorted(result["unsupported_categories"].items()))
    if not result["unsupported_categories"]:
        lines.append("- Нет")
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="path to a local OWASP BenchmarkPython checkout")
    parser.add_argument("--out", help="optional Markdown report path; default is stdout")
    args = parser.parse_args(argv)
    try:
        report = render_report(evaluate(args.root))
        if args.out:
            output = Path(args.out)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(report, encoding="utf-8")
        else:
            print(report, end="")
    except (OSError, ValueError) as error:
        print(f"Ошибка оценки: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
