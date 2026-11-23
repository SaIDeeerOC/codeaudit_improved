# CodeAudit — local code-quality pipeline and Git repository audit

A single offline tool that scans source code (bugs, vulnerabilities, code style, secrets)
and audits the full Git commit history. It scores a repository 0–100, decides whether the
quality gate is passed, and writes JSON / Markdown / HTML reports. Built for the MO-1
course project: automation of code-quality analysis and Git auditing in an
import-independent environment.

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)
![Dependencies](https://img.shields.io/badge/pip_dependencies-none-success)
![Network](https://img.shields.io/badge/network-not_required-success)
![Benchmark](https://img.shields.io/badge/benchmark_F1-1.00-blueviolet)

HTML report for the built-in demo repository:

![HTML report: score, run history, findings table](docs/report_screenshot.png)

## Quick start

Requirements: Python 3.11+ and git. Nothing else — no pip dependencies, no network access.

```
python3 run.py            # interactive menu (Windows: run.bat)
python3 run_demo.py       # self-contained demo: creates a repo with planted defects and audits it
python3 pipeline.py /path/to/repo --out report --config config.toml
```

## Example run (real demo output)

```
[..] builtin-python: работаю...
[ok] builtin-python: 3
[..] builtin-secrets: работаю...
[ok] builtin-secrets: 9
[..] git-audit: работаю...
  ... git-audit: в истории 1 коммитов
  ... git-audit: сканирую патчи всей истории на секреты
[ok] git-audit: 10
Оценка 0/100, high+critical=20, gate=FAILED; отчёты: demo_out/
Готово за 0.0 с
```

Console messages are intentionally in Russian (the course deliverable is localized);
findings, reports and JSON are fully parseable. Stage markers: `[..]` running, `[ok]` done,
`[--]` skipped (external tool not installed), `[!!]` stage error (does not stop the pipeline).

## What it checks

| Stage | External tool (optional) | Built-in implementation |
|---|---|---|
| Errors | ruff (F, B, E9) | syntax via `ast`, mutable default arguments, assert-on-tuple, redefined functions |
| Vulnerabilities | bandit, semgrep (local rules) | eval/exec, shell=True, SQL injection, pickle/yaml.load, weak hashes, disabled TLS, debug mode; regex rules for JS/TS, C/C++, PHP, Java, shell |
| Style | ruff (E, W, N, C90), shellcheck | unused and `*` imports, complexity, function/line length, naming, None comparison, trailing whitespace, EOF, indentation, TODO |
| Secrets | gitleaks | 11 secret kinds (see below) |
| Git history | gitleaks | secrets in every commit (including deleted), forbidden files, large blobs, huge commits, weak messages, future dates, unsigned commits, suspicious authors |

Secret detector covers 11 kinds: AWS access and secret keys, private keys, GitHub tokens,
Google API keys, Stripe keys, Slack tokens, Telegram bot tokens, JWT tokens,
credentials in URLs (`user:pass@host`), and passwords/tokens hardcoded in code.

## Built-in extras

- **Live progress.** Every stage prints its status; large repositories get a per-5000-files
  counter (stderr, so stdout stays machine-readable); total elapsed time at the end.
- **Scan cache.** File hashes are stored in `.scan_cache.json` inside the report folder;
  a repeated run rescans only changed files. Invalidated when `config.toml` changes;
  disable with `--no-cache`.
- **Run history.** Every run appends a line to `history.jsonl`; reports include a
  "Run history" section with score, high+critical count and gate verdict per run,
  plus the delta against the previous run.
- **Fault isolation.** A failing stage never stops the pipeline; external tools are used
  automatically when installed, built-in checks (stdlib + git only) always run offline.

## Scoring & quality gate

`score = max(0, 100 - sum(weights))` with weights: info 0, low 1, medium 3, high 8, critical 20.
The gate is passed when high+critical count ≤ `gate.max_high` and score ≥ `gate.min_score`
(both thresholds live in `config.toml`). Exit code 0 = gate passed, 1 = failed, 2 = usage error.

## Benchmark

`bench/bench.py` generates repositories with known planted defects (21 code defect types and
5 Git-history defect types), runs the pipeline and compares found (rule, file) pairs against
the ground truth: precision, recall, F1, false positives on clean repositories, quality-gate
accuracy and runtime. Full tables: [bench/results.md](bench/results.md).

30 defective repositories, 6 clean controls, 210 planted defect pairs:

| Category | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| error | 15 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| git | 48 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| secret | 19 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| style | 65 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| vulnerability | 63 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **total** | 210 | 0 | 0 | 1.00 | 1.00 | 1.00 |

- False positives on clean repositories: 0
- Correct quality-gate decisions: 36/36 (100%)
- Average analysis time per repository: 0.15 s (max 0.28 s)

### Limitations (for honest interpretation)

- The benchmark is synthetic (defects planted by the same authors as the rules), so F1 = 1.00
  proves the pipeline works and has no regressions, but is not a substitute for evaluation
  on real-world projects.
- External tools (ruff, bandit, semgrep, gitleaks, shellcheck) were not installed in the
  development environment; their integration is written from the documented output formats
  but has not been exercised. Verify locally with `pip install ruff bandit semgrep`.
- Deep AST analysis is Python-only; other languages use regex rules (possible false
  positives and misses), so semgrep and native linters matter for them.
- No taint/data-flow analysis: the rules flag dangerous constructs, not proven exploitability.
- Files larger than `max_file_kb` (1 MB) are skipped in the working-tree scan.

## License & docs

Course project documentation is in Russian: [README.md](README.md) (primary) and
[ЗАПУСК.md](ЗАПУСК.md) (step-by-step quick-start guide).
