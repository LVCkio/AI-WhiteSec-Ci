# K03 - Do tung rule Semgrep (security-config/semgrep/reports/r1_overlap_v22_2026-10-25_tuning_subset_uniq.csv)

So mau: 1149. Chi custom rules cua nhom (khong registry, khong Bandit). Precision = ti le bao DUNG lop tren mau co lo hong; khong do bao nham tren code an toan. Khong dung test.

## Bo rule theo ngon ngu x lop

Recall = ti le mau co it nhat 1 finding dung lop (bat ky tang / tang high).

| Ngon ngu | Lop | n | Recall v3 | Recall v4.0 | Recall v4.1 | Recall v4.2 | High v3 | High v4.0 | High v4.1 | High v4.2 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Java | PATH_TRAVERSAL | 27 | 0.19 | 0.19 | 0.19 | 0.19 | 0.00 | 0.00 | 0.00 | 0.00 |
| Java | SQL_INJECTION | 39 | 0.38 | 0.38 | 0.38 | 0.38 | 0.03 | 0.03 | 0.03 | 0.03 |
| Java | XSS | 22 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| JavaScript | OS_COMMAND_INJECTION | 73 | 0.08 | 0.08 | 0.29 | 0.29 | 0.00 | 0.00 | 0.00 | 0.00 |
| JavaScript | PATH_TRAVERSAL | 18 | 0.00 | 0.00 | 0.11 | 0.11 | 0.00 | 0.00 | 0.00 | 0.00 |
| JavaScript | SQL_INJECTION | 68 | 0.06 | 0.06 | 0.21 | 0.21 | 0.00 | 0.00 | 0.00 | 0.00 |
| JavaScript | XSS | 113 | 0.27 | 0.27 | 0.33 | 0.33 | 0.00 | 0.00 | 0.00 | 0.00 |
| PHP | AUTHENTICATION_WEAKNESS | 48 | 0.06 | 0.00 | 0.04 | 0.04 | 0.00 | 0.00 | 0.00 | 0.00 |
| PHP | HARDCODED_CREDENTIALS | 2 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| PHP | OS_COMMAND_INJECTION | 8 | 0.12 | 0.12 | 0.25 | 0.25 | 0.00 | 0.00 | 0.00 | 0.00 |
| PHP | PATH_TRAVERSAL | 94 | 0.04 | 0.04 | 0.17 | 0.04 | 0.04 | 0.04 | 0.04 | 0.00 |
| PHP | SQL_INJECTION | 155 | 0.35 | 0.35 | 0.57 | 0.57 | 0.08 | 0.08 | 0.08 | 0.08 |
| PHP | XSS | 335 | 0.12 | 0.12 | 0.21 | 0.23 | 0.04 | 0.05 | 0.05 | 0.05 |
| Python | AUTHENTICATION_WEAKNESS | 10 | 0.60 | 0.60 | 0.60 | 0.60 | 0.00 | 0.00 | 0.00 | 0.00 |
| Python | OS_COMMAND_INJECTION | 12 | 0.33 | 0.33 | 0.33 | 0.33 | 0.17 | 0.17 | 0.17 | 0.17 |
| Python | PATH_TRAVERSAL | 54 | 0.31 | 0.31 | 0.46 | 0.46 | 0.04 | 0.04 | 0.04 | 0.04 |
| Python | SQL_INJECTION | 19 | 0.68 | 0.37 | 0.37 | 0.37 | 0.00 | 0.05 | 0.05 | 0.05 |
| Python | XSS | 52 | 0.40 | 0.31 | 0.31 | 0.31 | 0.08 | 0.08 | 0.08 | 0.08 |
| **Tong** | | 1149 | **0.194** | **0.182** | **0.289** | **0.285** | 0.035 | 0.037 | 0.037 | 0.034 |

- v3: 312 lan rule bao (theo mau x rule), 256 dung lop -> precision lop 0.821

- v4.0: 283 lan rule bao (theo mau x rule), 238 dung lop -> precision lop 0.841

- v4.1: 548 lan rule bao (theo mau x rule), 449 dung lop -> precision lop 0.819

- v4.2: 540 lan rule bao (theo mau x rule), 454 dung lop -> precision lop 0.841

## Tung rule v4.2

| Rule | Tang | Ngon ngu | Bao | Dung lop | Precision | Chi rule nay bat dung |
|---|---|---|---:|---:|---:|---:|
| `team.php.audit.sql-api` | audit | PHP | 91 | 75 | 0.82 | 34 |
| `team.php.audit.echo-unescaped` | audit | PHP | 72 | 55 | 0.76 | 25 |
| `team.php.sqli-string` | audit | PHP | 58 | 50 | 0.86 | 14 |
| `team.php.xss-html-concat` | audit | PHP | 32 | 25 | 0.78 | 14 |
| `team.js.xss-html-concat` | audit | JavaScript | 24 | 24 | 1.00 | 12 |
| `team.php.xss-taint` | high | PHP | 24 | 17 | 0.71 | 2 |
| `team.js.audit.process-api` | audit | JavaScript | 21 | 21 | 1.00 | 15 |
| `team.php.audit.xss-template-echo` | audit | PHP | 20 | 14 | 0.70 | 7 |
| `team.js.xss-jquery-insert` | audit | JavaScript | 16 | 16 | 1.00 | 7 |
| `team.php.sqli-taint` | high | PHP | 14 | 12 | 0.86 | 0 |
| `team.py.audit.pathlib-api` | audit | Python | 13 | 13 | 1.00 | 8 |
| `team.xss-html-string-building` | audit | Python | 12 | 12 | 1.00 | 12 |
| `team.audit.file-path-api` | audit | Python | 12 | 11 | 0.92 | 1 |
| `team.path-from-parameter` | audit | Python | 12 | 12 | 1.00 | 3 |
| `team.java.sqli-concat` | audit | Java | 12 | 12 | 1.00 | 11 |
| `team.js.xss-dom-sink` | audit | JavaScript | 10 | 10 | 1.00 | 5 |
| `team.js.audit.sql-api` | audit | JavaScript | 10 | 10 | 1.00 | 10 |
| `team.js.audit.fs-path-api` | audit | JavaScript | 8 | 2 | 0.25 | 2 |
| `team.sql-string-building` | audit | Python | 6 | 6 | 1.00 | 4 |
| `team.php.xss-template-request` | high | PHP | 6 | 5 | 0.83 | 0 |
| `team.js.cmd-shell` | audit | JavaScript | 6 | 6 | 1.00 | 0 |
| `team.php.audit.auth-code` | audit | PHP | 6 | 2 | 0.33 | 2 |
| `team.audit.auth-code` | audit | Python | 6 | 6 | 1.00 | 6 |
| `team.java.audit.file-path-api` | audit | Java | 5 | 5 | 1.00 | 5 |
| `team.audit.html-output-api` | audit | Python | 4 | 0 | 0.00 | 0 |
| `team.php.path-taint` | audit | PHP | 4 | 4 | 1.00 | 4 |
| `team.js.sqli-string` | audit | JavaScript | 4 | 4 | 1.00 | 4 |
| `team.audit.process-api` | audit | Python | 4 | 4 | 1.00 | 2 |
| `team.php.hardcoded-secret` | high | PHP | 4 | 0 | 0.00 | 0 |
| `team.xss-unsafe-html` | high | Python | 4 | 4 | 1.00 | 4 |
| `team.audit.sql-api` | audit | Python | 3 | 3 | 1.00 | 0 |
| `team.java.audit.sql-api` | audit | Java | 3 | 3 | 1.00 | 3 |
| `team.path-request-taint` | high | Python | 2 | 2 | 1.00 | 0 |
| `team.archive-extract-all` | audit | Python | 2 | 2 | 1.00 | 0 |
| `team.os-command-injection` | high | Python | 2 | 2 | 1.00 | 0 |
| `team.php.audit.process-api` | audit | PHP | 2 | 2 | 1.00 | 1 |
| `team.py.xss-taint` | high | Python | 2 | 0 | 0.00 | 0 |
| `team.py.sqli-taint` | high | Python | 1 | 1 | 1.00 | 0 |
| `team.java.sqli-taint` | high | Java | 1 | 1 | 1.00 | 0 |
| `team.path-traversal` | high | Python | 1 | 0 | 0.00 | 0 |
| `team.php.cmd-dynamic` | audit | PHP | 1 | 1 | 1.00 | 0 |

Rule v4.2 khong bao lan nao (40): `team.auth-secret-equality`, `team.auth-session-fixation`, `team.auth-weak-password-hash`, `team.authentication-weakness`, `team.hardcoded-auth-header`, `team.hardcoded-credentials`, `team.java.audit.commandline-api`, `team.java.audit.process-api`, `team.java.audit.response-output`, `team.java.auth-jwt-unverified`, `team.java.auth-weak-password-hash`, `team.java.cmd-string`, `team.java.cmdi-taint`, `team.java.hardcoded-password-compare`, `team.java.hardcoded-secret`, `team.java.path-taint`, `team.java.path-upload-name`, `team.java.xss-html-concat`, `team.java.xss-taint`, `team.java.xss-writer-output`, `team.js.auth-jwt-decode`, `team.js.auth-jwt-unverified`, `team.js.auth-weak-password-hash`, `team.js.cmdi-taint`, `team.js.hardcoded-password-compare`, `team.js.hardcoded-secret`, `team.js.path-taint`, `team.js.sqli-dynamic-query`, `team.js.sqli-taint`, `team.js.xss-taint`, `team.os-command-string-building`, `team.php.auth-weak-password-hash`, `team.php.cmdi-taint`, `team.php.hardcoded-password-compare`, `team.py.audit.response-body`, `team.py.cmdi-taint`, `team.py.hardcoded-password-compare`, `team.py.xss-jinja-autoescape-default`, `team.sql-injection`, `team.xss-response-formatting`

## Rule `high` can xem lai (precision < 0,8 va >= 5 lan bao)

- `team.php.xss-taint`: 17/24 = 0.71
