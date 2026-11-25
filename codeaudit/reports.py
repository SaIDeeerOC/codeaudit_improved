import html
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .core import Finding, SEV, WEIGHT
from .suppressions import SuppressedFinding

REMEDIATION = {
    "dangerous-eval": "Замените динамическое выполнение явным разбором допустимых операций.",
    "sql-injection": "Используйте параметризованные запросы вместо сборки SQL из строк.",
    "shell-true": "Передавайте команду и аргументы списком; избегайте shell=True.",
    "hardcoded-credential": "Удалите секрет из кода, отзовите/замените его и храните вне репозитория.",
    "aws-access-key": "Отзовите ключ и проверьте историю Git: удаление из текущей версии недостаточно.",
    "private-key": "Считайте ключ скомпрометированным, замените его и удалите из истории Git.",
    "syntax-error": "Исправьте синтаксис в указанном файле и повторите проверку.",
    "tls-verify-disabled": "Включите проверку сертификата; не отключайте TLS-верификацию в production.",
    "weak-hash": "Для защиты целостности используйте современный криптографический хеш.",
}


def score_of(findings):
    return max(0, 100 - sum(WEIGHT[finding.severity] for finding in findings))


def _markdown_cell(value):
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


@dataclass(frozen=True)
class _ReportData:
    root: Path
    findings: list[Finding]
    suppressed_findings: list[SuppressedFinding]
    score: int
    gate_ok: bool
    notes: list[str]
    history: list[dict] | None
    delta: int | None
    elapsed: float | None
    scan_complete: bool
    severities: Counter
    categories: Counter


def _finding_location(finding):
    location = (f"{finding.file}:{finding.line}" if finding.file and finding.line else finding.file
                or (f"commit {finding.commit}" if finding.commit else ""))
    if finding.file and finding.commit:
        location += f" @{finding.commit}"
    return location


def _write_json_report(outdir, report, summary):
    data = {"summary": summary, "findings": [finding.__dict__ for finding in report.findings],
            "suppressed_findings": [
                {**item.finding.__dict__, "suppression_reason": item.reason,
                 "suppression_expires": item.expires}
                for item in report.suppressed_findings]}
    (outdir / "report.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _append_markdown_history(markdown, history, delta):
    if not history:
        return
    markdown.extend(["", "## Динамика проверок", ""])
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


def _append_markdown_findings(markdown, findings):
    markdown += ["", "## Находки", "",
                 "| Sev | Категория | Инструмент | Правило | Место | Описание |",
                 "|---|---|---|---|---|---|"]
    for finding in findings:
        values = (finding.severity, finding.category, finding.tool, finding.rule,
                  _finding_location(finding), finding.message)
        markdown.append("| " + " | ".join(_markdown_cell(value) for value in values) + " |")


def _append_markdown_suppressions(markdown, suppressed_findings):
    if not suppressed_findings:
        return
    markdown += ["", "## Исключённые находки", "",
                 "Не учитываются в оценке и quality gate; исключение видно для аудита.", "",
                 "| Sev | Категория | Правило | Место | Причина | Действует до |",
                 "|---|---|---|---|---|---|"]
    for item in suppressed_findings:
        finding = item.finding
        values = (finding.severity, finding.category, finding.rule,
                  _finding_location(finding), item.reason, item.expires)
        markdown.append("| " + " | ".join(_markdown_cell(value) for value in values) + " |")


def _write_markdown_report(outdir, report):
    markdown = [f"# Отчёт по качеству и аудиту: `{_markdown_cell(report.root.name)}`", "",
                f"**Оценка:** {report.score}/100  |  **Quality gate:** "
                f"{'ПРОЙДЕН' if report.gate_ok else 'НЕ ПРОЙДЕН'}"
                + (f"  |  Время анализа: {report.elapsed:.1f} с"
                   if report.elapsed is not None else ""), "",
                f"**Сканирование:** {'полное' if report.scan_complete else 'неполное'}", "",
                "| Критичность | Кол-во |", "|---|---|"]
    markdown += [f"| {severity} | {report.severities.get(severity, 0)} |" for severity in reversed(SEV)]
    markdown += ["", "Категории: " +
                 ", ".join(f"{key}: {value}" for key, value in report.categories.items()), ""]
    markdown += [f"_{_markdown_cell(note)}_" for note in report.notes]
    _append_markdown_history(markdown, report.history, report.delta)
    _append_markdown_findings(markdown, report.findings)
    _append_markdown_suppressions(markdown, report.suppressed_findings)
    (outdir / "report.md").write_text("\n".join(markdown), encoding="utf-8")


def _html_finding_row(finding, suppressed, reason, expires, color):
    location = _finding_location(finding)
    status = (f"Исключено до {html.escape(expires)}: {html.escape(reason)}"
              if suppressed else "Активная находка")
    fallback = "Проверьте контекст и исправьте находку либо зафиксируйте обоснованное исключение."
    remediation = ("Учтите исключение в установленный срок."
                   if suppressed else REMEDIATION.get(finding.rule, fallback))
    searchable = " ".join((finding.severity, finding.category, finding.tool, finding.rule,
                           location, finding.message, remediation, reason))
    return (f"<tr data-status=\"{'suppressed' if suppressed else 'active'}\" "
            f"data-severity=\"{html.escape(finding.severity)}\" "
            f"data-category=\"{html.escape(finding.category)}\" "
            f"data-search=\"{html.escape(searchable)}\">"
            f"<td style='color:{color[finding.severity]};font-weight:bold'>{html.escape(finding.severity)}</td>"
            f"<td>{html.escape(finding.category)}</td><td>{html.escape(finding.tool)}</td>"
            f"<td>{html.escape(finding.rule)}</td><td>{html.escape(location)}</td>"
            f"<td>{html.escape(finding.message)}</td><td>{html.escape(remediation)}</td>"
            f"<td>{status}</td></tr>")


def _history_html(report):
    if not report.history:
        return ""
    delta_html = (f"<p>К прошлому прогону: <b>{report.delta:+d}</b></p>"
                  if report.delta is not None
                  else "<p>Первый прогон в этой папке отчётов - сравнивать не с чем.</p>")
    rows = []
    for entry in report.history:
        high_count = int(entry.get("severities", {}).get("high", 0)) \
            + int(entry.get("severities", {}).get("critical", 0))
        rows.append(
            f"<tr><td>{html.escape(str(entry.get('date', '?')))}"
            f"{' - текущий' if entry.get('current') else ''}</td><td>{entry.get('score', '?')}</td>"
            f"<td>{high_count}</td><td>{int(entry.get('suppressed', 0))}</td>"
            f"<td>{'OK' if entry.get('gate') else 'FAILED'}</td></tr>")
    return (f"<h2>Динамика проверок</h2>{delta_html}<table>"
            f"<tr><th>Дата<th>Оценка<th>high+critical<th>Исключено<th>Gate</tr>"
            f"{''.join(rows)}</table>")


def _html_filters(report):
    categories = set(report.categories) | {item.finding.category
                                           for item in report.suppressed_findings}
    category_options = "".join(
        f"<option value=\"{html.escape(category)}\">{html.escape(category)}</option>"
        for category in sorted(categories))
    status_filter = ""
    if report.suppressed_findings:
        status_filter = (
            "<label>Статус <select id=\"status\"><option value=\"\">Все</option>"
            "<option value=\"active\">Активные</option>"
            "<option value=\"suppressed\">Исключённые</option></select></label>")
    severity_options = "".join(
        f"<option value=\"{html.escape(severity)}\">{html.escape(severity)}</option>"
        for severity in SEV)
    return (
        "<div class=\"filters\">"
        "<label>Поиск <input id=\"search\" type=\"search\" "
        "placeholder=\"Файл, правило или описание\"></label>"
        f"<label>Критичность <select id=\"severity\"><option value=\"\">Все</option>"
        f"{severity_options}</select></label>"
        f"<label>Категория <select id=\"category\"><option value=\"\">Все</option>"
        f"{category_options}</select></label>{status_filter}"
        "<span id=\"result-count\" aria-live=\"polite\"></span></div>")


def _html_table(report):
    color = {"critical": "#b00020", "high": "#d84315", "medium": "#f9a825",
             "low": "#558b2f", "info": "#607d8b"}
    display_rows = [(finding, False, "", "") for finding in report.findings]
    display_rows.extend((item.finding, True, item.reason, item.expires)
                        for item in report.suppressed_findings)
    rows = "".join(_html_finding_row(*row, color) for row in display_rows)
    titles = ("Sev", "Категория", "Инструмент", "Правило", "Место",
              "Описание", "Что проверить", "Статус / причина")
    headers = "".join(
        f'<th scope="col"><button type="button" data-sort="{index}">'
        f"{title} &#8597;</button></th>"
        for index, title in enumerate(titles))
    return (f'<table id="findings"><thead><tr>{headers}</tr></thead>'
            f"<tbody>{rows}</tbody></table>")


_HTML_SCRIPT = """<script>(()=>{const rows=[...document.querySelectorAll('#findings tbody tr')];
const body=document.querySelector('#findings tbody');
const controls=['search','severity','category','status'].map(id=>document.getElementById(id)).filter(Boolean);
const update=()=>{const q=(document.getElementById('search').value||'').toLocaleLowerCase();
let visible=0;for(const row of rows){const ok=(!q||row.dataset.search.toLocaleLowerCase().includes(q))&&
controls.every(c=>c.id==='search'||!c.value||row.dataset[c.id]===c.value);
row.hidden=!ok;if(ok)visible++;}document.getElementById('result-count').textContent=
`Показано ${visible} из ${rows.length}`;};
for(const control of controls)control.addEventListener(
control.tagName==='SELECT'?'change':'input',update);
for(const button of document.querySelectorAll('[data-sort]'))button.addEventListener('click',()=>{
const column=Number(button.dataset.sort),direction=button.dataset.direction==='asc'?-1:1;
const severityOrder=['critical','high','medium','low','info'];
rows.sort((a,b)=>{const x=a.cells[column].textContent.trim(),y=b.cells[column].textContent.trim();
if(column===0)return (severityOrder.indexOf(x)-severityOrder.indexOf(y))*direction;
return x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'})*direction;});
button.dataset.direction=direction===1?'asc':'desc';for(const row of rows)body.appendChild(row);update();});
update();})();</script>"""


def _write_html_report(report):
    notes_html = ("<h2>Примечания</h2><ul>" +
                  "".join(f"<li>{html.escape(str(note))}</li>" for note in report.notes) +
                  "</ul>") if report.notes else ""
    history_html = _history_html(report)
    severity_summary = ", ".join(
        f"{key}: {value}" for key, value in report.severities.items())
    return "".join((
        f"<!doctype html><meta charset=utf-8><title>Audit</title>"
        f"<style>body{{font:14px sans-serif;margin:2em;color:#202b36}}"
        f"table{{border-collapse:collapse;width:100%;margin-top:1em}}"
        f"td,th{{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}}"
        f"th{{position:sticky;top:0;background:#eef4f8}}"
        f".filters{{display:flex;gap:.6em;flex-wrap:wrap;margin:1em 0}}"
        f".filters input,.filters select{{padding:.5em;max-width:22em}}"
        f"th button{{font:inherit;font-weight:bold;border:0;background:transparent;cursor:pointer;padding:0}}"
        f"tr[hidden]{{display:none}}</style>"
        f"<h1>{html.escape(report.root.name)}: {report.score}/100 - gate "
        f"{'OK' if report.gate_ok else 'FAILED'}</h1>"
        f"<p>{severity_summary}</p>"
        f"<p>Сканирование {'полное' if report.scan_complete else 'неполное'}; "
        f"исключено с причиной и сроком: {len(report.suppressed_findings)}</p>"
        f"{notes_html}{history_html}"
        f"{_html_filters(report)}{_html_table(report)}{_HTML_SCRIPT}"))


def write_reports(outdir, root, findings, score, gate_ok, notes, history=None, delta=None,
                  elapsed=None, scan_complete=True, suppressed_findings=None):
    outdir.mkdir(parents=True, exist_ok=True)
    suppressed_findings = suppressed_findings or []
    findings = sorted(findings, key=lambda finding: (-SEV.index(finding.severity),
                                                      finding.category, finding.file))
    suppressed_findings = sorted(
        suppressed_findings,
        key=lambda item: (-SEV.index(item.finding.severity), item.finding.category, item.finding.file))
    severities = Counter(finding.severity for finding in findings)
    categories = Counter(finding.category for finding in findings)
    summary = {"repo": str(root), "date": datetime.now().isoformat(timespec="seconds"),
               "score": score, "gate_passed": gate_ok, "scan_complete": scan_complete,
               "by_severity": dict(severities), "by_category": dict(categories),
               "suppressed_count": len(suppressed_findings), "notes": notes}
    report = _ReportData(root, findings, suppressed_findings, score, gate_ok, notes,
                         history, delta, elapsed, scan_complete, severities, categories)
    _write_json_report(outdir, report, summary)
    _write_markdown_report(outdir, report)
    (outdir / "report.html").write_text(_write_html_report(report), encoding="utf-8")
