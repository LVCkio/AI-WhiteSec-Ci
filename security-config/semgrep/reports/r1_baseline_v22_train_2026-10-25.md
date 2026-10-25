# R1 · Đo nền Semgrep trên train dataset v2.2

- Ngày: 2026-10-25
- Dataset: v2.2 · file `train.jsonl` sha256 `dbf9cdf24edacda0f3af67115d5b3ecae800ba6aa05c54ae02db4411c496f77f`
- DATA_CARD sha256: `bc43638e1066c3a2b1ced5b82a52f9be37eae50296aed629bdfc04ad25cea9b1`
- Semgrep 1.181.0 · ruleset 4.3.1 · bundle sha256 `4141c05d256b41818f4b807d77274f0ce82b79545cba4dad5d6f0439d27632c3`
- Lệnh: `python 34_baseline_v22.py --split train`
- Chế độ dataset: mỗi mẫu quét riêng; đoạn hàm được bọc cho parse được (`wrap_fragment` của 03_run_sast.py).
- Không đọc, không quét tập test.

## 1. Tỉ lệ parse (đo trước khi diễn giải recall)

| Ngôn ngữ | Mẫu | ok | partial | failed | Tỉ lệ ok |
|---|---:|---:|---:|---:|---:|
| Python | 1074 | 1041 | 30 | 3 | 0.97 |
| Java | 1581 | 1485 | 69 | 27 | 0.94 |
| JavaScript | 2345 | 2020 | 265 | 60 | 0.86 |
| PHP | 3799 | 3701 | 96 | 2 | 0.97 |
| **Tổng** | 8799 | 8247 | 460 | 92 | 0.94 |

## 2. Bảng 24 ô (ngôn ngữ × lớp) – mẫu dương

Recall mẫu = mẫu có ≥ 1 finding đúng lớp / số mẫu. `parse ok` = số mẫu parse không lỗi.

| Lớp | Ngôn ngữ | n | parse ok | Recall high | Recall high+audit |
|---|---|---:|---:|---:|---:|
| SQL_INJECTION | Python | 13 | 13 | 0.08 (1) | 0.23 (3) |
| SQL_INJECTION | Java | 98 | 97 | 0.01 (1) | 0.41 (40) |
| SQL_INJECTION | JavaScript | 59 | 56 | 0.02 (1) | 0.29 (17) |
| SQL_INJECTION | PHP | 532 | 517 | 0.01 (7) | 0.37 (197) |
| **SQL_INJECTION** | *cả lớp* | 702 | | **0.01** | **0.37** |
| XSS | Python | 106 | 106 | 0.32 (34) | 0.39 (41) |
| XSS | Java | 113 | 111 | 0.00 (0) | 0.04 (4) |
| XSS | JavaScript | 536 | 461 | 0.01 (4) | 0.28 (149) |
| XSS | PHP | 507 | 488 | 0.03 (16) | 0.18 (89) |
| **XSS** | *cả lớp* | 1262 | | **0.04** | **0.22** |
| OS_COMMAND_INJECTION | Python | 46 | 46 | 0.33 (15) | 0.39 (18) |
| OS_COMMAND_INJECTION | Java | 39 | 39 | 0.00 (0) | 0.26 (10) |
| OS_COMMAND_INJECTION | JavaScript | 77 | 72 | 0.01 (1) | 0.38 (29) |
| OS_COMMAND_INJECTION | PHP | 66 | 65 | 0.00 (0) | 0.20 (13) |
| **OS_COMMAND_INJECTION** | *cả lớp* | 228 | | **0.07** | **0.31** |
| PATH_TRAVERSAL | Python | 74 | 74 | 0.01 (1) | 0.39 (29) |
| PATH_TRAVERSAL | Java | 141 | 141 | 0.01 (2) | 0.33 (46) |
| PATH_TRAVERSAL | JavaScript | 54 | 49 | 0.00 (0) | 0.24 (13) |
| PATH_TRAVERSAL | PHP | 23 | 23 | 0.00 (0) | 0.00 (0) |
| **PATH_TRAVERSAL** | *cả lớp* | 292 | | **0.01** | **0.30** |
| INSECURE_AUTHENTICATION | Python | 73 | 73 | 0.00 (0) | 0.05 (4) |
| INSECURE_AUTHENTICATION | Java | 114 | 114 | 0.00 (0) | 0.00 (0) |
| INSECURE_AUTHENTICATION | JavaScript | 16 | 12 | 0.00 (0) | 0.00 (0) |
| INSECURE_AUTHENTICATION | PHP | 53 | 51 | 0.00 (0) | 0.06 (3) |
| **INSECURE_AUTHENTICATION** | *cả lớp* | 256 | | **0.00** | **0.03** |
| HARDCODED_CREDENTIALS | Python | 56 | 40 | 0.66 (37) | 0.66 (37) |
| HARDCODED_CREDENTIALS | Java | 145 | 86 | 0.27 (39) | 0.27 (39) |
| HARDCODED_CREDENTIALS | JavaScript | 49 | 28 | 0.53 (26) | 0.53 (26) |
| HARDCODED_CREDENTIALS | PHP | 52 | 36 | 0.10 (5) | 0.10 (5) |
| **HARDCODED_CREDENTIALS** | *cả lớp* | 302 | | **0.35** | **0.35** |
| **Tổng mẫu dương** | | 3042 | | **0.06** | **0.27** |

### Tách theo `over_512` (mẫu dương)

| over_512 | n | Recall high | Recall high+audit |
|---|---:|---:|---:|
| false | 1893 | 0.07 | 0.25 |
| true | 1149 | 0.06 | 0.30 |

## 3. Tỉ lệ đúng lớp (không phải precision)

Trên mẫu dương: 1007/1271 cặp (mẫu, rule) báo đúng lớp = **0.79**.

## 4. Tỉ lệ báo nhầm trên mẫu âm

| Ngôn ngữ | Mẫu âm | Có finding (bất kỳ tầng) | Có finding high | Tỉ lệ (bất kỳ) | Tỉ lệ (high) |
|---|---:|---:|---:|---:|---:|
| Python | 706 | 163 | 47 | 0.23 | 0.07 |
| Java | 931 | 123 | 14 | 0.13 | 0.02 |
| JavaScript | 1554 | 280 | 15 | 0.18 | 0.01 |
| PHP | 2566 | 564 | 44 | 0.22 | 0.02 |
| Tổng | 5757 | 1130 | 120 | 0.20 | 0.02 |

## 5. Từng rule (TC4 trên split này)

Ngưỡng: high ≥ 0,80; audit ≥ 0,50; cần ≥ 5 lần báo trên mẫu dương. `Mẫu âm` = số mẫu âm rule báo.

| Rule | Tầng | Báo (mẫu dương) | Đúng lớp | Tỉ lệ | Mẫu âm | TC4 |
|---|---|---:|---:|---:|---:|---|
| `team.php.audit.sql-api` | audit | 199 | 170 | 0.85 | 236 | dat |
| `team.js.xss-dom-sink` | audit | 103 | 90 | 0.87 | 120 | dat |
| `team.php.audit.echo-unescaped` | audit | 100 | 67 | 0.67 | 175 | dat |
| `team.php.xss-html-concat` | audit | 93 | 39 | 0.42 | 156 | rot (audit < 0.50) |
| `team.java.audit.file-path-api` | audit | 63 | 46 | 0.73 | 80 | dat |
| `team.js.xss-html-concat` | audit | 59 | 52 | 0.88 | 62 | dat |
| `team.php.sqli-string` | audit | 54 | 33 | 0.61 | 89 | dat |
| `team.hardcoded-credentials` | high | 44 | 37 | 0.84 | 28 | dat |
| `team.java.hardcoded-secret` | high | 41 | 39 | 0.95 | 10 | dat |
| `team.java.sqli-concat` | audit | 38 | 37 | 0.97 | 11 | dat |
| `team.js.xss-jquery-insert` | audit | 36 | 36 | 1.00 | 49 | dat |
| `team.xss-unsafe-html` | high | 32 | 32 | 1.00 | 11 | dat |
| `team.audit.file-path-api` | audit | 28 | 9 | 0.32 | 36 | rot (audit < 0.50) |
| `team.js.audit.process-api` | audit | 28 | 27 | 0.96 | 18 | dat |
| `team.js.hardcoded-secret` | high | 27 | 26 | 0.96 | 10 | dat |
| `team.js.audit.fs-path-api` | audit | 22 | 13 | 0.59 | 39 | dat |
| `team.py.audit.pathlib-api` | audit | 22 | 17 | 0.77 | 24 | dat |
| `team.php.xss-taint` | high | 21 | 16 | 0.76 | 30 | rot (high < 0.80) |
| `team.xss-html-string-building` | audit | 21 | 19 | 0.90 | 9 | dat |
| `team.audit.process-api` | audit | 19 | 18 | 0.95 | 20 | dat |
| `team.java.audit.sql-api` | audit | 16 | 16 | 1.00 | 8 | dat |
| `team.js.audit.sql-api` | audit | 16 | 14 | 0.88 | 18 | dat |
| `team.php.audit.process-api` | audit | 16 | 13 | 0.81 | 17 | dat |
| `team.os-command-injection` | high | 12 | 12 | 1.00 | 4 | dat |
| `team.path-from-parameter` | audit | 12 | 10 | 0.83 | 18 | dat |
| `team.php.audit.xss-template-echo` | audit | 11 | 10 | 0.91 | 16 | dat |
| `team.php.sqli-taint` | high | 11 | 7 | 0.64 | 13 | rot (high < 0.80) |
| `team.audit.html-output-api` | audit | 9 | 9 | 1.00 | 32 | dat |
| `team.java.audit.commandline-api` | audit | 9 | 9 | 1.00 | 12 | dat |
| `team.js.cmd-shell` | audit | 9 | 9 | 1.00 | 2 | dat |
| `team.php.audit.auth-code` | audit | 9 | 3 | 0.33 | 13 | rot (audit < 0.50) |
| `team.audit.auth-code` | audit | 8 | 3 | 0.38 | 9 | rot (audit < 0.50) |
| `team.php.cmd-dynamic` | audit | 8 | 8 | 1.00 | 7 | dat |
| `team.js.sqli-string` | audit | 7 | 6 | 0.86 | 7 | dat |
| `team.java.xss-html-concat` | audit | 6 | 4 | 0.67 | 7 | dat |
| `team.php.hardcoded-secret` | high | 5 | 4 | 0.80 | 1 | dat |
| `team.py.xss-jinja-autoescape-default` | audit | 5 | 3 | 0.60 | 3 | dat |
| `team.py.xss-taint` | high | 5 | 5 | 1.00 | 0 | dat |
| `team.archive-extract-all` | audit | 4 | 4 | 1.00 | 5 | chua du du lieu (<5) |
| `team.js.xss-taint` | high | 4 | 4 | 1.00 | 4 | chua du du lieu (<5) |
| `team.os-command-string-building` | high | 4 | 4 | 1.00 | 2 | chua du du lieu (<5) |
| `team.sql-string-building` | audit | 4 | 3 | 0.75 | 2 | chua du du lieu (<5) |
| `team.audit.sql-api` | audit | 3 | 3 | 1.00 | 2 | chua du du lieu (<5) |
| `team.php.hardcoded-password-compare` | high | 3 | 1 | 0.33 | 2 | chua du du lieu (<5) |
| `team.auth-secret-equality` | audit | 2 | 2 | 1.00 | 1 | chua du du lieu (<5) |
| `team.java.audit.response-output` | audit | 2 | 0 | 0.00 | 1 | chua du du lieu (<5) |
| `team.java.path-taint` | high | 2 | 2 | 1.00 | 2 | chua du du lieu (<5) |
| `team.js.sqli-dynamic-query` | audit | 2 | 2 | 1.00 | 2 | chua du du lieu (<5) |
| `team.php.xss-template-request` | high | 2 | 2 | 1.00 | 1 | chua du du lieu (<5) |
| `team.xss-response-formatting` | high | 2 | 2 | 1.00 | 1 | chua du du lieu (<5) |
| `team.java.audit.process-api` | audit | 1 | 1 | 1.00 | 1 | chua du du lieu (<5) |
| `team.java.auth-weak-password-hash` | audit | 1 | 0 | 0.00 | 2 | chua du du lieu (<5) |
| `team.java.path-upload-name` | audit | 1 | 1 | 1.00 | 1 | chua du du lieu (<5) |
| `team.java.sqli-taint` | high | 1 | 1 | 1.00 | 2 | chua du du lieu (<5) |
| `team.java.xss-taint` | high | 1 | 0 | 0.00 | 0 | chua du du lieu (<5) |
| `team.js.cmdi-taint` | high | 1 | 1 | 1.00 | 0 | chua du du lieu (<5) |
| `team.js.sqli-taint` | high | 1 | 1 | 1.00 | 1 | chua du du lieu (<5) |
| `team.path-request-taint` | high | 1 | 1 | 1.00 | 1 | chua du du lieu (<5) |
| `team.php.auth-weak-password-hash` | audit | 1 | 1 | 1.00 | 2 | chua du du lieu (<5) |
| `team.php.path-taint` | audit | 1 | 0 | 0.00 | 2 | chua du du lieu (<5) |
| `team.py.cmdi-taint` | high | 1 | 1 | 1.00 | 1 | chua du du lieu (<5) |
| `team.py.hardcoded-password-compare` | high | 1 | 1 | 1.00 | 0 | chua du du lieu (<5) |
| `team.sql-injection` | high | 1 | 1 | 1.00 | 2 | chua du du lieu (<5) |
| `team.js.auth-jwt-decode` | audit | 0 | 0 | - | 1 | chua du du lieu (<5) |
| `team.js.auth-weak-password-hash` | audit | 0 | 0 | - | 1 | chua du du lieu (<5) |

Rule không báo lần nào trên train (16): `team.auth-session-fixation`, `team.auth-weak-password-hash`, `team.authentication-weakness`, `team.hardcoded-auth-header`, `team.java.auth-jwt-unverified`, `team.java.cmd-string`, `team.java.cmdi-taint`, `team.java.hardcoded-password-compare`, `team.java.xss-writer-output`, `team.js.auth-jwt-unverified`, `team.js.hardcoded-password-compare`, `team.js.path-taint`, `team.path-traversal`, `team.php.cmdi-taint`, `team.py.audit.response-body`, `team.py.sqli-taint`

## Điều chưa chắc chắn

- Mẫu là đoạn hàm cắt ra; `wrap_fragment` bọc thêm class/`<?php` để parse. Mẫu parse lỗi vẫn được tính vào mẫu số recall.
- `module_snippet` (HARDCODED, nguồn CredData) là ±5 dòng quanh credential, có thể không phải code hoàn chỉnh.
- Taint của Semgrep CE chỉ trong một hàm; đơn vị mẫu là một hàm nên luồng liên hàm không được tính.
- Tỉ lệ đúng lớp tính trên mẫu dương, không đo báo nhầm trên code an toàn; báo nhầm xem mục 4.
- Nhãn của phần lớn mẫu là UNREVIEWED theo DATA_CARD v2.2.
- Bộ rule v4.x đã được chỉnh trên dữ liệu v5/a01 trùng repo với một phần v2.2 (xem r1_overlap_v22): số trên train/val v2.2 có thể lạc quan.
