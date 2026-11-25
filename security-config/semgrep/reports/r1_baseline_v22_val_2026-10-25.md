# R1 · Đo nền Semgrep trên val dataset v2.2

- Ngày: 2026-10-25
- Dataset: v2.2 · file `val.jsonl` sha256 `f59df7639a39c2fa72168f6fe2de01add4b850cde9839c01e0b2c7786e4ce305`
- DATA_CARD sha256: `bc43638e1066c3a2b1ced5b82a52f9be37eae50296aed629bdfc04ad25cea9b1`
- Semgrep 1.181.0 · ruleset 4.3.1 · bundle sha256 `4141c05d256b41818f4b807d77274f0ce82b79545cba4dad5d6f0439d27632c3`
- Lệnh: `python 34_baseline_v22.py --split val`
- Chế độ dataset: mỗi mẫu quét riêng; đoạn hàm được bọc cho parse được (`wrap_fragment` của 03_run_sast.py).
- Không đọc, không quét tập test.

## 1. Tỉ lệ parse (đo trước khi diễn giải recall)

| Ngôn ngữ | Mẫu | ok | partial | failed | Tỉ lệ ok |
|---|---:|---:|---:|---:|---:|
| Python | 223 | 215 | 7 | 1 | 0.96 |
| Java | 159 | 150 | 9 | 0 | 0.94 |
| JavaScript | 388 | 299 | 75 | 14 | 0.77 |
| PHP | 475 | 472 | 3 | 0 | 0.99 |
| **Tổng** | 1245 | 1136 | 94 | 15 | 0.91 |

## 2. Bảng 24 ô (ngôn ngữ × lớp) – mẫu dương

Recall mẫu = mẫu có ≥ 1 finding đúng lớp / số mẫu. `parse ok` = số mẫu parse không lỗi.

| Lớp | Ngôn ngữ | n | parse ok | Recall high | Recall high+audit |
|---|---|---:|---:|---:|---:|
| SQL_INJECTION | Python | 3 | 3 | 0.67 (2) | 0.67 (2) |
| SQL_INJECTION | Java | 20 | 20 | 0.00 (0) | 0.70 (14) |
| SQL_INJECTION | JavaScript | 0 | 0 | - (0) | - (0) |
| SQL_INJECTION | PHP | 45 | 45 | 0.02 (1) | 0.64 (29) |
| **SQL_INJECTION** | *cả lớp* | 68 | | **0.04** | **0.66** |
| XSS | Python | 13 | 13 | 0.15 (2) | 0.38 (5) |
| XSS | Java | 14 | 14 | 0.00 (0) | 0.00 (0) |
| XSS | JavaScript | 73 | 48 | 0.00 (0) | 0.47 (34) |
| XSS | PHP | 67 | 66 | 0.07 (5) | 0.22 (15) |
| **XSS** | *cả lớp* | 167 | | **0.04** | **0.32** |
| OS_COMMAND_INJECTION | Python | 14 | 14 | 0.29 (4) | 0.36 (5) |
| OS_COMMAND_INJECTION | Java | 0 | 0 | - (0) | - (0) |
| OS_COMMAND_INJECTION | JavaScript | 38 | 31 | 0.00 (0) | 0.16 (6) |
| OS_COMMAND_INJECTION | PHP | 5 | 5 | 0.00 (0) | 0.00 (0) |
| **OS_COMMAND_INJECTION** | *cả lớp* | 57 | | **0.07** | **0.19** |
| PATH_TRAVERSAL | Python | 13 | 13 | 0.00 (0) | 0.62 (8) |
| PATH_TRAVERSAL | Java | 10 | 10 | 0.00 (0) | 0.60 (6) |
| PATH_TRAVERSAL | JavaScript | 13 | 10 | 0.00 (0) | 0.46 (6) |
| PATH_TRAVERSAL | PHP | 7 | 7 | 0.00 (0) | 0.00 (0) |
| **PATH_TRAVERSAL** | *cả lớp* | 43 | | **0.00** | **0.47** |
| INSECURE_AUTHENTICATION | Python | 18 | 18 | 0.00 (0) | 0.06 (1) |
| INSECURE_AUTHENTICATION | Java | 4 | 3 | 0.00 (0) | 0.00 (0) |
| INSECURE_AUTHENTICATION | JavaScript | 6 | 5 | 0.00 (0) | 0.00 (0) |
| INSECURE_AUTHENTICATION | PHP | 5 | 5 | 0.00 (0) | 0.60 (3) |
| **INSECURE_AUTHENTICATION** | *cả lớp* | 33 | | **0.00** | **0.12** |
| HARDCODED_CREDENTIALS | Python | 9 | 9 | 0.44 (4) | 0.44 (4) |
| HARDCODED_CREDENTIALS | Java | 5 | 2 | 0.20 (1) | 0.20 (1) |
| HARDCODED_CREDENTIALS | JavaScript | 5 | 4 | 0.60 (3) | 0.60 (3) |
| HARDCODED_CREDENTIALS | PHP | 4 | 3 | 0.50 (2) | 0.50 (2) |
| **HARDCODED_CREDENTIALS** | *cả lớp* | 23 | | **0.43** | **0.43** |
| **Tổng mẫu dương** | | 391 | | **0.06** | **0.37** |

### Tách theo `over_512` (mẫu dương)

| over_512 | n | Recall high | Recall high+audit |
|---|---:|---:|---:|
| false | 217 | 0.07 | 0.36 |
| true | 174 | 0.05 | 0.38 |

## 3. Tỉ lệ đúng lớp (không phải precision)

Trên mẫu dương: 212/232 cặp (mẫu, rule) báo đúng lớp = **0.91**.

## 4. Tỉ lệ báo nhầm trên mẫu âm

| Ngôn ngữ | Mẫu âm | Có finding (bất kỳ tầng) | Có finding high | Tỉ lệ (bất kỳ) | Tỉ lệ (high) |
|---|---:|---:|---:|---:|---:|
| Python | 153 | 38 | 10 | 0.25 | 0.07 |
| Java | 106 | 22 | 2 | 0.21 | 0.02 |
| JavaScript | 253 | 50 | 0 | 0.20 | 0.00 |
| PHP | 342 | 73 | 8 | 0.21 | 0.02 |
| Tổng | 854 | 183 | 20 | 0.21 | 0.02 |

## 5. Từng rule (TC4 trên split này)

Ngưỡng: high ≥ 0,80; audit ≥ 0,50; cần ≥ 5 lần báo trên mẫu dương. `Mẫu âm` = số mẫu âm rule báo.

| Rule | Tầng | Báo (mẫu dương) | Đúng lớp | Tỉ lệ | Mẫu âm | TC4 |
|---|---|---:|---:|---:|---:|---|
| `team.php.audit.sql-api` | audit | 26 | 26 | 1.00 | 35 | dat |
| `team.js.xss-dom-sink` | audit | 25 | 25 | 1.00 | 22 | dat |
| `team.js.xss-html-concat` | audit | 20 | 20 | 1.00 | 21 | dat |
| `team.php.sqli-string` | audit | 19 | 19 | 1.00 | 30 | dat |
| `team.java.audit.sql-api` | audit | 14 | 14 | 1.00 | 9 | dat |
| `team.php.audit.echo-unescaped` | audit | 14 | 11 | 0.79 | 20 | dat |
| `team.path-from-parameter` | audit | 8 | 6 | 0.75 | 4 | dat |
| `team.java.audit.file-path-api` | audit | 7 | 6 | 0.86 | 11 | dat |
| `team.java.sqli-concat` | audit | 7 | 7 | 1.00 | 0 | dat |
| `team.audit.file-path-api` | audit | 6 | 4 | 0.67 | 11 | dat |
| `team.js.audit.fs-path-api` | audit | 6 | 6 | 1.00 | 8 | dat |
| `team.js.audit.process-api` | audit | 6 | 6 | 1.00 | 9 | dat |
| `team.php.audit.xss-template-echo` | audit | 6 | 6 | 1.00 | 5 | dat |
| `team.php.xss-html-concat` | audit | 6 | 6 | 1.00 | 13 | dat |
| `team.audit.process-api` | audit | 5 | 5 | 1.00 | 5 | dat |
| `team.php.audit.auth-code` | audit | 5 | 3 | 0.60 | 7 | dat |
| `team.php.xss-taint` | high | 5 | 5 | 1.00 | 5 | dat |
| `team.audit.html-output-api` | audit | 4 | 2 | 0.50 | 7 | chua du du lieu (<5) |
| `team.hardcoded-credentials` | high | 4 | 4 | 1.00 | 1 | chua du du lieu (<5) |
| `team.js.xss-jquery-insert` | audit | 4 | 4 | 1.00 | 3 | chua du du lieu (<5) |
| `team.os-command-injection` | high | 4 | 4 | 1.00 | 2 | chua du du lieu (<5) |
| `team.audit.sql-api` | audit | 3 | 2 | 0.67 | 3 | chua du du lieu (<5) |
| `team.js.hardcoded-secret` | high | 3 | 3 | 1.00 | 0 | chua du du lieu (<5) |
| `team.audit.auth-code` | audit | 2 | 1 | 0.50 | 4 | chua du du lieu (<5) |
| `team.java.xss-html-concat` | audit | 2 | 0 | 0.00 | 2 | chua du du lieu (<5) |
| `team.js.cmd-shell` | audit | 2 | 2 | 1.00 | 1 | chua du du lieu (<5) |
| `team.py.audit.pathlib-api` | audit | 2 | 2 | 1.00 | 3 | chua du du lieu (<5) |
| `team.py.xss-taint` | high | 2 | 1 | 0.50 | 2 | chua du du lieu (<5) |
| `team.sql-injection` | high | 2 | 2 | 1.00 | 0 | chua du du lieu (<5) |
| `team.xss-html-string-building` | audit | 2 | 2 | 1.00 | 4 | chua du du lieu (<5) |
| `team.java.audit.response-output` | audit | 1 | 0 | 0.00 | 1 | chua du du lieu (<5) |
| `team.java.hardcoded-secret` | high | 1 | 1 | 1.00 | 0 | chua du du lieu (<5) |
| `team.java.xss-taint` | high | 1 | 0 | 0.00 | 1 | chua du du lieu (<5) |
| `team.java.xss-writer-output` | audit | 1 | 0 | 0.00 | 1 | chua du du lieu (<5) |
| `team.php.hardcoded-password-compare` | high | 1 | 1 | 1.00 | 0 | chua du du lieu (<5) |
| `team.php.hardcoded-secret` | high | 1 | 1 | 1.00 | 1 | chua du du lieu (<5) |
| `team.php.sqli-taint` | high | 1 | 1 | 1.00 | 2 | chua du du lieu (<5) |
| `team.php.xss-template-request` | high | 1 | 1 | 1.00 | 0 | chua du du lieu (<5) |
| `team.py.sqli-taint` | high | 1 | 1 | 1.00 | 0 | chua du du lieu (<5) |
| `team.sql-string-building` | audit | 1 | 1 | 1.00 | 1 | chua du du lieu (<5) |
| `team.xss-unsafe-html` | high | 1 | 1 | 1.00 | 5 | chua du du lieu (<5) |
| `team.java.path-taint` | high | 0 | 0 | - | 1 | chua du du lieu (<5) |
| `team.java.path-upload-name` | audit | 0 | 0 | - | 2 | chua du du lieu (<5) |
| `team.js.sqli-string` | audit | 0 | 0 | - | 1 | chua du du lieu (<5) |
| `team.php.audit.process-api` | audit | 0 | 0 | - | 1 | chua du du lieu (<5) |
| `team.php.path-taint` | audit | 0 | 0 | - | 1 | chua du du lieu (<5) |
| `team.py.audit.response-body` | audit | 0 | 0 | - | 2 | chua du du lieu (<5) |

Rule không báo lần nào trên val (34): `team.archive-extract-all`, `team.auth-secret-equality`, `team.auth-session-fixation`, `team.auth-weak-password-hash`, `team.authentication-weakness`, `team.hardcoded-auth-header`, `team.java.audit.commandline-api`, `team.java.audit.process-api`, `team.java.auth-jwt-unverified`, `team.java.auth-weak-password-hash`, `team.java.cmd-string`, `team.java.cmdi-taint`, `team.java.hardcoded-password-compare`, `team.java.sqli-taint`, `team.js.audit.sql-api`, `team.js.auth-jwt-decode`, `team.js.auth-jwt-unverified`, `team.js.auth-weak-password-hash`, `team.js.cmdi-taint`, `team.js.hardcoded-password-compare`, `team.js.path-taint`, `team.js.sqli-dynamic-query`, `team.js.sqli-taint`, `team.js.xss-taint`, `team.os-command-string-building`, `team.path-request-taint`, `team.path-traversal`, `team.php.auth-weak-password-hash`, `team.php.cmd-dynamic`, `team.php.cmdi-taint`, `team.py.cmdi-taint`, `team.py.hardcoded-password-compare`, `team.py.xss-jinja-autoescape-default`, `team.xss-response-formatting`

## Điều chưa chắc chắn

- Mẫu là đoạn hàm cắt ra; `wrap_fragment` bọc thêm class/`<?php` để parse. Mẫu parse lỗi vẫn được tính vào mẫu số recall.
- `module_snippet` (HARDCODED, nguồn CredData) là ±5 dòng quanh credential, có thể không phải code hoàn chỉnh.
- Taint của Semgrep CE chỉ trong một hàm; đơn vị mẫu là một hàm nên luồng liên hàm không được tính.
- Tỉ lệ đúng lớp tính trên mẫu dương, không đo báo nhầm trên code an toàn; báo nhầm xem mục 4.
- Nhãn của phần lớn mẫu là UNREVIEWED theo DATA_CARD v2.2.
- Bộ rule v4.x đã được chỉnh trên dữ liệu v5/a01 trùng repo với một phần v2.2 (xem r1_overlap_v22): số trên train/val v2.2 có thể lạc quan.
