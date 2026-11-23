#!/bin/sh
# cp pre-push-hook.sh .git/hooks/pre-push && chmod +x .git/hooks/pre-push
python3 "$(git rev-parse --show-toplevel)/pipeline.py" "$(git rev-parse --show-toplevel)" --out /tmp/audit-report \
  || { echo "Quality gate не пройден: /tmp/audit-report/report.md"; exit 1; }
