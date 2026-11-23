Репозиториев с дефектами: 30, чистых контрольных: 6. Внедрено дефектов (пар правило+файл): 210.

| Правило | Категория | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| mutable-default | error | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| syntax-error | error | 8 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| forbidden-file | git | 12 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| huge-commit | git | 12 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| large-blob | git | 12 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| weak-message | git | 12 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| aws-access-key | secret | 12 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| hardcoded-credential | secret | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| bare-except | style | 8 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| high-complexity | style | 8 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| line-too-long | style | 8 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| missing-eof-newline | style | 6 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| none-comparison | style | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| todo-marker | style | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| trailing-whitespace | style | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| unused-import | style | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| wildcard-import | style | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| c-unsafe-func | vulnerability | 6 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| dangerous-eval | vulnerability | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| js-eval | vulnerability | 6 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| sh-curl-pipe | vulnerability | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| shell-true | vulnerability | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| sql-injection | vulnerability | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| tls-verify-disabled | vulnerability | 8 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| unsafe-deserialization | vulnerability | 8 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| weak-hash | vulnerability | 7 | 0 | 0 | 1.00 | 1.00 | 1.00 |

| Категория | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| error | 15 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| git | 48 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| secret | 19 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| style | 65 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| vulnerability | 63 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **всего** | 210 | 0 | 0 | 1.00 | 1.00 | 1.00 |

- Ложные срабатывания на чистых репозиториях: 0
- Верных решений quality gate: 36/36 (100%)
- Среднее время анализа репозитория: 0.15 с (макс. 0.28 с)