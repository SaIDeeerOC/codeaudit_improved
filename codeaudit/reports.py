import html
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from pathlib import PureWindowsPath
from urllib.parse import quote

from .core import Finding, SEV, WEIGHT, atomic_write_text
from .fingerprints import fingerprinted_findings
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
    baseline_findings: list[Finding]
    suppressed_findings: list[SuppressedFinding]
    score: int
    gate_ok: bool
    notes: list[str]
    history: list[dict] | None
    delta: int | None
    elapsed: float | None
    scan_complete: bool
    coverage: dict
    finding_changes: dict
    provenance: dict
    fingerprints: dict
    severities: Counter
    categories: Counter


def _finding_location(finding):
    location = (f"{finding.file}:{finding.line}" if finding.file and finding.line else finding.file
                or (f"commit {finding.commit}" if finding.commit else ""))
    if finding.file and finding.commit:
        location += f" @{finding.commit}"
    return location


def _sarif_rule_id(finding):
    return f"{finding.tool}/{finding.rule}"


def _sarif_level(severity):
    return "error" if severity in ("high", "critical") else "warning" if severity == "medium" else "note"


def _sarif_uri(filename):
    windows_path = PureWindowsPath(filename)
    if windows_path.is_absolute() and not Path(filename).is_absolute():
        return windows_path.as_uri(), False
    path = Path(filename)
    if path.is_absolute():
        return path.as_uri(), False
    return quote(path.as_posix(), safe="/-._~"), True


def _sarif_result(finding, rule_index, fingerprint, suppressed=None, baseline=False):
    result = {
        "ruleId": _sarif_rule_id(finding),
        "ruleIndex": rule_index,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message},
        "properties": {"category": finding.category, "tool": finding.tool,
                       "severity": finding.severity},
    }
    if baseline:
        result["baselineState"] = "unchanged"
        result["properties"]["baseline"] = True
    if finding.file:
        uri, relative = _sarif_uri(finding.file)
        artifact = {"uri": uri}
        if relative:
            artifact["uriBaseId"] = "%SRCROOT%"
        physical_location = {"artifactLocation": artifact}
        if finding.line > 0:
            physical_location["region"] = {"startLine": finding.line}
        result["locations"] = [{"physicalLocation": physical_location}]
    if finding.commit:
        result["properties"]["commit"] = finding.commit
    if suppressed is not None:
        result["suppressions"] = [{
            "kind": "external",
            "status": "accepted",
            "justification": f"{suppressed.reason} (expires {suppressed.expires})",
        }]
    result["partialFingerprints"] = {"codeaudit/v2": fingerprint}
    return result


def _sarif_document(report):
    findings = [(finding, None, False) for finding in report.findings]
    findings.extend((finding, None, True) for finding in report.baseline_findings)
    findings.extend((item.finding, item, False) for item in report.suppressed_findings)
    visible = [finding for finding, _, _ in findings]
    fallback = {id(finding): fingerprint for fingerprint, finding in fingerprinted_findings(visible)}
    fingerprints = [report.fingerprints.get(id(finding), fallback[id(finding)])
                    for finding in visible]
    rule_levels = {}
    rule_properties = {}
    for finding, _, _ in findings:
        rule_id = _sarif_rule_id(finding)
        level = _sarif_level(finding.severity)
        rank = {"note": 0, "warning": 1, "error": 2}
        if rule_id not in rule_levels or rank[level] > rank[rule_levels[rule_id]]:
            rule_levels[rule_id] = level
        rule_properties[rule_id] = {"category": finding.category, "tool": finding.tool}

    rule_ids = sorted(rule_levels)
    rule_indices = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = [{
        "id": rule_id,
        "name": rule_id.rsplit("/", 1)[-1],
        "shortDescription": {"text": rule_id.rsplit("/", 1)[-1]},
        "defaultConfiguration": {"level": rule_levels[rule_id]},
        "properties": rule_properties[rule_id],
    } for rule_id in rule_ids]
    results = [
        _sarif_result(finding, rule_indices[_sarif_rule_id(finding)], fingerprint,
                      suppressed, baseline)
        for (finding, suppressed, baseline), fingerprint in zip(findings, fingerprints)
    ]
    source_uri = report.root.resolve().as_uri()
    if not source_uri.endswith("/"):
        source_uri += "/"
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeAudit", "rules": rules}},
            "invocations": [{"executionSuccessful": report.scan_complete}],
            "originalUriBaseIds": {"%SRCROOT%": {"uri": source_uri}},
            "results": results,
            "properties": {
                "score": report.score,
                "gatePassed": report.gate_ok,
                "scanComplete": report.scan_complete,
                "coverage": report.coverage,
                "provenance": report.provenance,
                "findingChanges": report.finding_changes,
            },
        }],
    }


def _write_json_report(outdir, report, summary):
    visible = [*report.findings, *report.baseline_findings]
    fallback = {id(finding): fingerprint for fingerprint, finding in fingerprinted_findings(visible)}
    fingerprint_of = lambda finding: report.fingerprints.get(id(finding), fallback[id(finding)])
    data = {"summary": summary,
            "findings": [{**finding.__dict__, "fingerprint": fingerprint_of(finding)}
                         for finding in report.findings],
            "baseline_findings": [{**finding.__dict__, "fingerprint": fingerprint_of(finding)}
                                  for finding in report.baseline_findings],
            "suppressed_findings": [
                {**item.finding.__dict__, "suppression_reason": item.reason,
                 "suppression_expires": item.expires}
                for item in report.suppressed_findings],
            "coverage": report.coverage,
            "finding_changes": report.finding_changes,
            "provenance": report.provenance}
    atomic_write_text(outdir / "report.json", json.dumps(data, ensure_ascii=False, indent=2))


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


def _append_markdown_changes(markdown, changes):
    markdown.extend(["", "## Изменения находок между запусками", ""])
    if not changes.get("available"):
        markdown.append("Сравнение не выполнялось: нет предыдущего полного сканирования "
                        "или текущий прогон неполный.")
        return
    for key, title in (("new", "Новые"), ("reopened", "Повторно появившиеся"),
                       ("resolved", "Устранённые")):
        items = changes.get(key, [])
        markdown.extend([f"### {title}: {len(items)}", ""])
        if items:
            markdown.extend(
                f"- `{_markdown_cell(item.get('rule', '?'))}` — "
                f"`{_markdown_cell(item.get('file', ''))}`:{item.get('line', 0)} "
                f"({item.get('severity', 'info')})"
                for item in items)
        else:
            markdown.append("Нет.")


def _append_markdown_provenance(markdown, provenance):
    markdown.extend(["", "## Воспроизводимость", ""])
    for label, key in (
            ("Commit", "repository_commit"), ("Ref", "repository_ref"),
            ("CodeAudit", "codeaudit_version"), ("Python", "python_version"),
            ("Конфигурация SHA-256", "config_fingerprint"),
            ("Локальные правила SHA-256", "local_rules_fingerprint")):
        markdown.append(f"- **{label}:** `{_markdown_cell(provenance.get(key) or 'не определено')}`")
    markdown.append("- **Версии анализаторов:** " + _markdown_cell(
        ", ".join(f"{name} {version}" for name, version
                  in provenance.get("tool_versions", {}).items()) or "не обнаружены"))


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
                f"**Совпавших baseline-находок:** {len(report.baseline_findings)}", "",
                "| Критичность | Кол-во |", "|---|---|"]
    markdown += [f"| {severity} | {report.severities.get(severity, 0)} |" for severity in reversed(SEV)]
    markdown += ["", "Категории: " +
                 ", ".join(f"{key}: {value}" for key, value in report.categories.items()), ""]
    markdown.extend([
        "## Охват сканирования",
        "",
        f"Файлов-кандидатов: {report.coverage['files_considered']}; "
        f"сверх лимита размера: {report.coverage['size_limited_files']}; "
        f"ошибок доступа: {report.coverage['errors']}.",
    ])
    if report.coverage["issues"]:
        markdown += ["", "| Файл | Причина | Подробности | Блокирует gate |", "|---|---|---|---|"]
        markdown.extend(
            f"| {_markdown_cell(issue['file'])} | {_markdown_cell(issue['reason'])} | "
            f"{_markdown_cell(issue['detail'])} | {'да' if issue['blocks_gate'] else 'нет'} |"
            for issue in report.coverage["issues"])
    markdown.append("")
    markdown += [f"_{_markdown_cell(note)}_" for note in report.notes]
    _append_markdown_provenance(markdown, report.provenance)
    _append_markdown_history(markdown, report.history, report.delta)
    _append_markdown_changes(markdown, report.finding_changes)
    _append_markdown_findings(markdown, report.findings)
    if report.baseline_findings:
        markdown.extend(["", "## Совпавшие находки baseline", "",
                         "Показаны отдельно; не учитываются в score и quality gate.", "",
                         "| Sev | Категория | Инструмент | Правило | Место | Описание |",
                         "|---|---|---|---|---|---|"])
        for finding in report.baseline_findings:
            values = (finding.severity, finding.category, finding.tool, finding.rule,
                      _finding_location(finding), finding.message)
            markdown.append("| " + " | ".join(_markdown_cell(value) for value in values) + " |")
    _append_markdown_suppressions(markdown, report.suppressed_findings)
    atomic_write_text(outdir / "report.md", "\n".join(markdown))


def _html_finding_row(finding, suppressed, reason, expires, color, baseline=False):
    location = _finding_location(finding)
    status = (f"Исключено до {html.escape(expires)}: {html.escape(reason)}"
              if suppressed else "Baseline (не влияет на score/gate)" if baseline
              else "Активная находка")
    fallback = "Проверьте контекст и исправьте находку либо зафиксируйте обоснованное исключение."
    remediation = ("Учтите исключение в установленный срок."
                   if suppressed else REMEDIATION.get(finding.rule, fallback))
    searchable = " ".join((finding.severity, finding.category, finding.tool, finding.rule,
                           location, finding.message, remediation, reason))
    row_status = "suppressed" if suppressed else "baseline" if baseline else "active"
    return (f"<tr data-status=\"{row_status}\" "
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
    categories.update(finding.category for finding in report.baseline_findings)
    category_options = "".join(
        f"<option value=\"{html.escape(category)}\">{html.escape(category)}</option>"
        for category in sorted(categories))
    status_filter = ""
    if report.suppressed_findings or report.baseline_findings:
        status_filter = (
            "<label>Статус <select id=\"status\"><option value=\"\">Все</option>"
            "<option value=\"active\">Активные</option>"
            "<option value=\"baseline\">Baseline</option>"
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
    display_rows = [(finding, False, "", "", color, False) for finding in report.findings]
    display_rows.extend((finding, False, "", "", color, True) for finding in report.baseline_findings)
    display_rows.extend((item.finding, True, item.reason, item.expires, color, False)
                        for item in report.suppressed_findings)
    rows = "".join(_html_finding_row(*row) for row in display_rows)
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
    coverage_html = _coverage_html(report.coverage)
    changes_html = _changes_html(report.finding_changes)
    provenance_html = _provenance_html(report.provenance)
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
        f"baseline: {len(report.baseline_findings)}; "
        f"исключено с причиной и сроком: {len(report.suppressed_findings)}</p>"
        f"{notes_html}{provenance_html}{history_html}{changes_html}{coverage_html}"
        f"{_html_filters(report)}{_html_table(report)}{_HTML_SCRIPT}"))


def _changes_html(changes):
    if not changes.get("available"):
        return "<h2>Изменения находок между запусками</h2><p>Сравнение недоступно: " \
               "нужны два полных сканирования.</p>"
    rows = []
    for key, label in (("new", "Новые"), ("reopened", "Повторно появившиеся"),
                       ("resolved", "Устранённые")):
        for item in changes.get(key, []):
            rows.append(
                f"<tr><td>{label}</td><td>{html.escape(str(item.get('rule', '?')))}</td>"
                f"<td>{html.escape(str(item.get('file', '')))}:{int(item.get('line', 0))}</td>"
                f"<td>{html.escape(str(item.get('severity', 'info')))}</td></tr>")
    table = ("<table><tr><th>Статус<th>Правило<th>Файл<th>Критичность</tr>"
             + "".join(rows) + "</table>") if rows else "<p>Изменений нет.</p>"
    return "<h2>Изменения находок между запусками</h2>" + table


def _provenance_html(provenance):
    rows = [
        ("Commit", provenance.get("repository_commit")),
        ("Ref", provenance.get("repository_ref")),
        ("CodeAudit", provenance.get("codeaudit_version")),
        ("Python", provenance.get("python_version")),
        ("Конфигурация SHA-256", provenance.get("config_fingerprint")),
        ("Локальные правила SHA-256", provenance.get("local_rules_fingerprint")),
        ("Версии анализаторов", ", ".join(
            f"{name} {version}" for name, version in provenance.get("tool_versions", {}).items())
         or "не обнаружены"),
    ]
    return ("<h2>Воспроизводимость</h2><table><tr><th>Параметр<th>Значение</tr>"
            + "".join(f"<tr><td>{html.escape(str(key))}</td><td>{html.escape(str(value or 'не определено'))}</td></tr>"
                      for key, value in rows) + "</table>")


def _coverage_html(coverage):
    rows = "".join(
        f"<tr><td>{html.escape(issue['file'])}</td><td>{html.escape(issue['reason'])}</td>"
        f"<td>{html.escape(issue['detail'])}</td>"
        f"<td>{'Да' if issue['blocks_gate'] else 'Нет'}</td></tr>"
        for issue in coverage["issues"])
    table = (f"<table><tr><th>Файл<th>Причина<th>Подробности<th>Блокирует gate</tr>{rows}</table>"
             if rows else "<p>Пропущенных файлов и ошибок доступа не обнаружено.</p>")
    return (f"<h2>Охват сканирования</h2><p>Файлов-кандидатов: "
            f"{coverage['files_considered']}; сверх лимита размера: {coverage['size_limited_files']}; "
            f"ошибок доступа: {coverage['errors']}.</p>{table}")


def write_reports(outdir, root, findings, score, gate_ok, notes, history=None, delta=None,
                  elapsed=None, scan_complete=True, suppressed_findings=None, coverage=None,
                  baseline_findings=None, finding_changes=None, provenance=None, fingerprints=None):
    outdir.mkdir(parents=True, exist_ok=True)
    suppressed_findings = suppressed_findings or []
    baseline_findings = baseline_findings or []
    finding_changes = finding_changes or {"available": False, "new": [], "reopened": [], "resolved": []}
    provenance = provenance or {}
    fingerprints = fingerprints or {}
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
               "suppressed_count": len(suppressed_findings),
               "baseline_count": len(baseline_findings), "notes": notes,
               "finding_changes": finding_changes, "provenance": provenance}
    coverage = coverage or {"files_considered": 0, "size_limited_files": 0, "errors": 0, "issues": []}
    summary["coverage"] = coverage
    report = _ReportData(root, findings, baseline_findings, suppressed_findings, score, gate_ok, notes,
                         history, delta, elapsed, scan_complete, coverage,
                         finding_changes, provenance, fingerprints, severities, categories)
    _write_json_report(outdir, report, summary)
    _write_markdown_report(outdir, report)
    atomic_write_text(outdir / "report.html", _write_html_report(report))
    atomic_write_text(outdir / "report.sarif", json.dumps(_sarif_document(report), ensure_ascii=False, indent=2))
