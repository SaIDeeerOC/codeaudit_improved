import html
import json
from collections import Counter
from datetime import datetime

from .core import SEV, WEIGHT


def score_of(findings):
    return max(0, 100 - sum(WEIGHT[finding.severity] for finding in findings))


def _markdown_cell(value):
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def write_reports(outdir, root, findings, score, gate_ok, notes, history=None, delta=None,
                  elapsed=None, scan_complete=True):
    outdir.mkdir(parents=True, exist_ok=True)
    findings = sorted(findings, key=lambda finding: (-SEV.index(finding.severity),
                                                      finding.category, finding.file))
    severities = Counter(finding.severity for finding in findings)
    categories = Counter(finding.category for finding in findings)
    summary = {"repo": str(root), "date": datetime.now().isoformat(timespec="seconds"),
               "score": score, "gate_passed": gate_ok, "scan_complete": scan_complete,
               "by_severity": dict(severities), "by_category": dict(categories), "notes": notes}
    (outdir / "report.json").write_text(
        json.dumps({"summary": summary, "findings": [finding.__dict__ for finding in findings]},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    markdown = [f"# Отчёт по качеству и аудиту: `{_markdown_cell(root.name)}`", "",
                f"**Оценка:** {score}/100  |  **Quality gate:** {'ПРОЙДЕН' if gate_ok else 'НЕ ПРОЙДЕН'}"
                + (f"  |  Время анализа: {elapsed:.1f} с" if elapsed is not None else ""), "",
                f"**Сканирование:** {'полное' if scan_complete else 'неполное'}", "",
                "| Критичность | Кол-во |", "|---|---|"]
    markdown += [f"| {severity} | {severities.get(severity, 0)} |" for severity in reversed(SEV)]
    markdown += ["", "Категории: " + ", ".join(f"{key}: {value}" for key, value in categories.items()), ""]
    markdown += [f"_{_markdown_cell(note)}_" for note in notes]
    if history:
        markdown += ["", "## Динамика проверок", ""]
        markdown.append(f"К прошлому прогону: **{delta:+d}**" if delta is not None
                        else "Первый прогон в этой папке отчётов - сравнивать не с чем.")
        markdown += ["", "| Дата | Оценка | high+critical | Gate |", "|---|---|---|---|"]
        for entry in history:
            values = entry.get("severities", {})
            high_count = int(values.get("high", 0)) + int(values.get("critical", 0))
            mark = " - текущий" if entry.get("current") else ""
            markdown.append(f"| {_markdown_cell(entry.get('date', '?'))}{mark} | "
                            f"{entry.get('score', '?')} | {high_count} | "
                            f"{'OK' if entry.get('gate') else 'FAILED'} |")
    markdown += ["", "## Находки", "",
                 "| Sev | Категория | Инструмент | Правило | Место | Описание |",
                 "|---|---|---|---|---|---|"]
    for finding in findings:
        location = (f"{finding.file}:{finding.line}" if finding.file and finding.line else finding.file
                    or (f"commit {finding.commit}" if finding.commit else ""))
        if finding.file and finding.commit:
            location += f" @{finding.commit}"
        values = (finding.severity, finding.category, finding.tool, finding.rule, location, finding.message)
        markdown.append("| " + " | ".join(_markdown_cell(value) for value in values) + " |")
    (outdir / "report.md").write_text("\n".join(markdown), encoding="utf-8")

    color = {"critical": "#b00020", "high": "#d84315", "medium": "#f9a825",
             "low": "#558b2f", "info": "#607d8b"}
    rows = "".join(
        f"<tr><td style='color:{color[finding.severity]};font-weight:bold'>{finding.severity}</td>"
        f"<td>{html.escape(finding.category)}</td><td>{html.escape(finding.tool)}</td>"
        f"<td>{html.escape(finding.rule)}</td>"
        f"<td>{html.escape(finding.file)}{':' + str(finding.line) if finding.line else ''} "
        f"{html.escape(finding.commit)}</td><td>{html.escape(finding.message)}</td></tr>"
        for finding in findings)
    history_html = ""
    if history:
        delta_html = (f"<p>К прошлому прогону: <b>{delta:+d}</b></p>" if delta is not None
                      else "<p>Первый прогон в этой папке отчётов - сравнивать не с чем.</p>")
        history_rows = "".join(
            f"<tr><td>{html.escape(str(entry.get('date', '?')))}"
            f"{' - текущий' if entry.get('current') else ''}</td><td>{entry.get('score', '?')}</td>"
            f"<td>{int(entry.get('severities', {}).get('high', 0)) + int(entry.get('severities', {}).get('critical', 0))}</td>"
            f"<td>{'OK' if entry.get('gate') else 'FAILED'}</td></tr>" for entry in history)
        history_html = (f"<h2>Динамика проверок</h2>{delta_html}<table>"
                        f"<tr><th>Дата<th>Оценка<th>high+critical<th>Gate</tr>{history_rows}</table>")
    (outdir / "report.html").write_text(
        f"<!doctype html><meta charset=utf-8><title>Audit</title>"
        f"<style>body{{font:14px sans-serif;margin:2em}}table{{border-collapse:collapse}}"
        f"td,th{{border:1px solid #ccc;padding:4px 8px}}</style>"
        f"<h1>{html.escape(root.name)}: {score}/100 - gate {'OK' if gate_ok else 'FAILED'}</h1>"
        f"<p>{', '.join(f'{key}: {value}' for key, value in severities.items())}</p>"
        f"<p>Сканирование {'полное' if scan_complete else 'неполное'}</p>{history_html}"
        f"<table><tr><th>Sev<th>Категория<th>Инструмент<th>Правило<th>Место<th>Описание</tr>{rows}</table>",
        encoding="utf-8")
