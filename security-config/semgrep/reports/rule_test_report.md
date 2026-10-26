# Ket qua kiem tra ruleset v4.6.1

- Thoi diem: 2026-10-26T05:53:02+00:00
- Semgrep: 1.181.0 (ghim 1.181.0); taxonomy: 0.3.0
- So rule: 79; van de metadata/do phu: 0
- Test: 306/306 dat; loi: 0
- ruleset_sha256: `bff761dd3726fa3a094109e30dc3d6f62612254d4cf135e3a1e627ac2b863986`
- **regression_passed: True**

## Ngoai le tang high/audit da ghi ly do (4)

- `team.php.path-taint` (rule_version 1.2.0): Taint nhung o audit (ngoai le semgrep_tool.md 5.2). Train v5 chi dung lop 7/13 = 0,54: dat nguong audit 0,50, chua dat high 0,80 (TC4). Rot TC5-audit (ban va 10 > ban loi 7) nhung giu vi la rule PHP PATH_TRAVERSAL gan nhu duy nhat; can ra tay cac hit tren train v2.2 truoc khi quyet dinh giu hay tat.
- `team.php.sqli-taint` (rule_version 1.1.0): Taint nhung o audit (ngoai le semgrep_tool.md 5.2): train v2.2 dung lop 7/11 = 0,64, dat nguong audit 0,50 nhung chua dat high 0,80 (TC4); val v2.2 < 5 lan bao. Xet lai len high khi do lai tren train/val v2.2 >= 0,80.
- `team.php.xss-taint` (rule_version 1.2.0): Taint nhung o audit (ngoai le semgrep_tool.md 5.2): sau khi them sanitizer, train v2.2 dung lop 13/17 = 0,76 (< 0,80 high, >= 0,50 audit); val v2.2 5/5. Nhieu mau am tren train co echo $_GET that (nhan sai), nen chua ket luan duoc pattern sai. Xet lai len high khi nhan v2.3 duoc ra soat.
- `team.path-from-parameter` (rule_version 1.1.0): Taint nhung giu audit (ngoai le semgrep_tool.md 5.2). Source la moi tham so ham, khong phai du lieu request, nen chi biet gia tri co the do ben ngoai dua vao, khong chac la dau vao nguoi dung. Train v5: 30/34 = 0,88 dung lop, val v5: 4/4 (< 5 hit, chua du de len high theo TC4). Xet lai len high khi val v2.2 co >= 5 hit va >= 0,80.

## Canh bao theo semgrep_tool.md (22)

- rules\java\authentication_weakness.yml::team.java.auth-jwt-unverified: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\java\authentication_weakness.yml::team.java.auth-weak-password-hash: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\java\authentication_weakness.yml::team.java.auth-weak-password-hash: CWE-916 xep vao INSECURE_AUTHENTICATION theo metadata, cho xac nhan (taxonomy open_questions)
- rules\java\sql_injection.yml::team.java.sqli-concat: dung pattern-regex nhung khong co paths.include (5.2: chi dung regex khi parser khong doc duoc file)
- rules\java\xss.yml::team.java.xss-html-concat: dung pattern-regex nhung khong co paths.include (5.2: chi dung regex khi parser khong doc duoc file)
- rules\javascript\authentication_weakness.yml::team.js.auth-jwt-unverified: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\javascript\authentication_weakness.yml::team.js.auth-jwt-decode: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\javascript\authentication_weakness.yml::team.js.auth-weak-password-hash: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\javascript\authentication_weakness.yml::team.js.auth-weak-password-hash: CWE-916 xep vao INSECURE_AUTHENTICATION theo metadata, cho xac nhan (taxonomy open_questions)
- rules\javascript\sql_injection.yml::team.js.sqli-string: dung pattern-regex nhung khong co paths.include (5.2: chi dung regex khi parser khong doc duoc file)
- rules\javascript\xss.yml::team.js.xss-html-concat: dung pattern-regex nhung khong co paths.include (5.2: chi dung regex khi parser khong doc duoc file)
- rules\php\authentication_weakness.yml::team.php.auth-weak-password-hash: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\php\authentication_weakness.yml::team.php.auth-weak-password-hash: CWE-916 xep vao INSECURE_AUTHENTICATION theo metadata, cho xac nhan (taxonomy open_questions)
- rules\php\sql_injection.yml::team.php.sqli-string: dung pattern-regex nhung khong co paths.include (5.2: chi dung regex khi parser khong doc duoc file)
- rules\python\authentication_weakness.yml::team.authentication-weakness: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\python\authentication_weakness.yml::team.auth-secret-equality: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\python\authentication_weakness.yml::team.auth-session-fixation: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\python\authentication_weakness.yml::team.auth-session-fixation: CWE-384 khong thuoc danh sach CWE cua INSECURE_AUTHENTICATION trong taxonomy.yml (TC1)
- rules\python\authentication_weakness.yml::team.auth-weak-password-hash: vuln_class AUTHENTICATION_WEAKNESS la ten cu, taxonomy dung INSECURE_AUTHENTICATION (doi ten trong mot dot rieng)
- rules\python\authentication_weakness.yml::team.auth-weak-password-hash: CWE-916 xep vao INSECURE_AUTHENTICATION theo metadata, cho xac nhan (taxonomy open_questions)
- rules\python\sql_injection.yml::team.sql-string-building: dung pattern-regex nhung khong co paths.include (5.2: chi dung regex khi parser khong doc duoc file)
- rules\python\xss.yml::team.xss-html-string-building: dung pattern-regex nhung khong co paths.include (5.2: chi dung regex khi parser khong doc duoc file)

## Chi tiet tung truong hop

| File | Dong | Rule | Ky vong | Ket qua |
|---|---:|---|---|---|
| tests/negative/java/authentication_weakness.java | 11 | `team.java.auth-jwt-unverified` | khong bao | dat |
| tests/negative/java/authentication_weakness.java | 17 | `team.java.auth-weak-password-hash` | khong bao | dat |
| tests/negative/java/hardcoded_credentials.java | 10 | `team.java.hardcoded-secret` | khong bao | dat |
| tests/negative/java/hardcoded_credentials.java | 12 | `team.java.hardcoded-secret` | khong bao | dat |
| tests/negative/java/hardcoded_credentials.java | 16 | `team.java.hardcoded-password-compare` | khong bao | dat |
| tests/negative/java/hardcoded_credentials.java | 18 | `team.java.hardcoded-password-compare` | khong bao | dat |
| tests/negative/java/os_command_injection.java | 12 | `team.java.cmdi-taint` | khong bao | dat |
| tests/negative/java/os_command_injection.java | 12 | `team.java.cmd-string` | khong bao | dat |
| tests/negative/java/os_command_injection.java | 14 | `team.java.audit.process-api` | khong bao | dat |
| tests/negative/java/os_command_injection.java | 14 | `team.java.cmdi-taint` | khong bao | dat |
| tests/negative/java/os_command_injection.java | 17 | `team.java.cmdi-taint` | khong bao | dat |
| tests/negative/java/os_command_injection.java | 25 | `team.java.audit.commandline-api` | khong bao | dat |
| tests/negative/java/os_command_injection.java | 27 | `team.java.audit.commandline-api` | khong bao | dat |
| tests/negative/java/path_traversal.java | 12 | `team.java.path-taint` | khong bao | dat |
| tests/negative/java/path_traversal.java | 14 | `team.java.audit.file-path-api` | khong bao | dat |
| tests/negative/java/path_traversal.java | 14 | `team.java.path-taint` | khong bao | dat |
| tests/negative/java/path_traversal.java | 19 | `team.java.path-upload-name` | khong bao | dat |
| tests/negative/java/sql_injection.java | 13 | `team.java.sqli-taint` | khong bao | dat |
| tests/negative/java/sql_injection.java | 17 | `team.java.sqli-taint` | khong bao | dat |
| tests/negative/java/sql_injection.java | 19 | `team.java.audit.sql-api` | khong bao | dat |
| tests/negative/java/sql_injection.java | 19 | `team.java.sqli-concat` | khong bao | dat |
| tests/negative/java/sql_injection.java | 26 | `team.java.sqli-taint` | khong bao | dat |
| tests/negative/java/xss.java | 12 | `team.java.xss-taint` | khong bao | dat |
| tests/negative/java/xss.java | 14 | `team.java.audit.response-output` | khong bao | dat |
| tests/negative/java/xss.java | 14 | `team.java.xss-html-concat` | khong bao | dat |
| tests/negative/java/xss.java | 22 | `team.java.xss-writer-output` | khong bao | dat |
| tests/negative/java/xss.java | 24 | `team.java.xss-writer-output` | khong bao | dat |
| tests/negative/java/xss.java | 26 | `team.java.xss-writer-output` | khong bao | dat |
| tests/negative/javascript/authentication_weakness.js | 11 | `team.js.auth-jwt-unverified` | khong bao | dat |
| tests/negative/javascript/authentication_weakness.js | 11 | `team.js.auth-jwt-decode` | khong bao | dat |
| tests/negative/javascript/authentication_weakness.js | 13 | `team.js.auth-weak-password-hash` | khong bao | dat |
| tests/negative/javascript/hardcoded_credentials.js | 10 | `team.js.hardcoded-secret` | khong bao | dat |
| tests/negative/javascript/hardcoded_credentials.js | 12 | `team.js.hardcoded-secret` | khong bao | dat |
| tests/negative/javascript/hardcoded_credentials.js | 16 | `team.js.hardcoded-password-compare` | khong bao | dat |
| tests/negative/javascript/hardcoded_credentials.js | 18 | `team.js.hardcoded-password-compare` | khong bao | dat |
| tests/negative/javascript/hardcoded_credentials.js | 24 | `team.js.hardcoded-password-compare` | khong bao | dat |
| tests/negative/javascript/os_command_injection.js | 11 | `team.js.cmdi-taint` | khong bao | dat |
| tests/negative/javascript/os_command_injection.js | 11 | `team.js.cmd-shell` | khong bao | dat |
| tests/negative/javascript/os_command_injection.js | 13 | `team.js.cmd-shell` | khong bao | dat |
| tests/negative/javascript/os_command_injection.js | 13 | `team.js.cmdi-taint` | khong bao | dat |
| tests/negative/javascript/os_command_injection.js | 19 | `team.js.audit.process-api` | khong bao | dat |
| tests/negative/javascript/os_command_injection.js | 21 | `team.js.audit.process-api` | khong bao | dat |
| tests/negative/javascript/path_traversal.js | 11 | `team.js.path-taint` | khong bao | dat |
| tests/negative/javascript/path_traversal.js | 13 | `team.js.path-taint` | khong bao | dat |
| tests/negative/javascript/path_traversal.js | 19 | `team.js.audit.fs-path-api` | khong bao | dat |
| tests/negative/javascript/path_traversal.js | 21 | `team.js.audit.fs-path-api` | khong bao | dat |
| tests/negative/javascript/path_traversal.js | 28 | `team.js.audit.fs-path-api` | khong bao | dat |
| tests/negative/javascript/path_traversal.js | 30 | `team.js.audit.fs-path-api` | khong bao | dat |
| tests/negative/javascript/sql_injection.js | 12 | `team.js.sqli-taint` | khong bao | dat |
| tests/negative/javascript/sql_injection.js | 12 | `team.js.sqli-string` | khong bao | dat |
| tests/negative/javascript/sql_injection.js | 15 | `team.js.sqli-taint` | khong bao | dat |
| tests/negative/javascript/sql_injection.js | 21 | `team.js.sqli-dynamic-query` | khong bao | dat |
| tests/negative/javascript/sql_injection.js | 23 | `team.js.sqli-dynamic-query` | khong bao | dat |
| tests/negative/javascript/sql_injection.js | 29 | `team.js.audit.sql-api` | khong bao | dat |
| tests/negative/javascript/sql_injection.js | 31 | `team.js.audit.sql-api` | khong bao | dat |
| tests/negative/javascript/xss.js | 11 | `team.js.xss-taint` | khong bao | dat |
| tests/negative/javascript/xss.js | 13 | `team.js.xss-taint` | khong bao | dat |
| tests/negative/javascript/xss.js | 13 | `team.js.xss-html-concat` | khong bao | dat |
| tests/negative/javascript/xss.js | 18 | `team.js.xss-dom-sink` | khong bao | dat |
| tests/negative/javascript/xss.js | 20 | `team.js.xss-dom-sink` | khong bao | dat |
| tests/negative/javascript/xss.js | 26 | `team.js.xss-jquery-insert` | khong bao | dat |
| tests/negative/javascript/xss.js | 28 | `team.js.xss-jquery-insert` | khong bao | dat |
| tests/negative/javascript/xss.js | 30 | `team.js.xss-jquery-insert` | khong bao | dat |
| tests/negative/php/authentication_weakness.php | 5 | `team.php.auth-weak-password-hash` | khong bao | dat |
| tests/negative/php/authentication_weakness.php | 7 | `team.php.auth-weak-password-hash` | khong bao | dat |
| tests/negative/php/hardcoded_credentials.php | 3 | `team.php.hardcoded-secret` | khong bao | dat |
| tests/negative/php/hardcoded_credentials.php | 7 | `team.php.hardcoded-password-compare` | khong bao | dat |
| tests/negative/php/hardcoded_credentials.php | 9 | `team.php.hardcoded-password-compare` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 5 | `team.php.cmdi-taint` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 5 | `team.php.cmd-dynamic` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 7 | `team.php.cmdi-taint` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 7 | `team.php.cmd-dynamic` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 13 | `team.php.audit.process-api` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 21 | `team.php.audit.gitphp-unescaped-argument` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 23 | `team.php.audit.gitphp-unescaped-argument` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 25 | `team.php.audit.gitphp-unescaped-argument` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 27 | `team.php.audit.gitphp-unescaped-argument` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 29 | `team.php.audit.gitphp-unescaped-argument` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 36 | `team.php.audit.gitphp-unescaped-argument` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 38 | `team.php.audit.gitphp-unescaped-argument` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 44 | `team.php.audit.gitphp-unescaped-argument` | khong bao | dat |
| tests/negative/php/os_command_injection.php | 51 | `team.php.audit.gitphp-unescaped-argument` | khong bao | dat |
| tests/negative/php/path_traversal.php | 5 | `team.php.path-taint` | khong bao | dat |
| tests/negative/php/sql_injection.php | 5 | `team.php.sqli-taint` | khong bao | dat |
| tests/negative/php/sql_injection.php | 7 | `team.php.sqli-taint` | khong bao | dat |
| tests/negative/php/sql_injection.php | 7 | `team.php.sqli-string` | khong bao | dat |
| tests/negative/php/sql_injection.php | 13 | `team.php.audit.sql-api` | khong bao | dat |
| tests/negative/php/sql_injection.php | 15 | `team.php.audit.sql-api` | khong bao | dat |
| tests/negative/php/sql_injection.php | 17 | `team.php.audit.sql-api` | khong bao | dat |
| tests/negative/php/sql_injection.php | 23 | `team.php.audit.query-single-dynamic-where` | khong bao | dat |
| tests/negative/php/sql_injection.php | 25 | `team.php.audit.query-single-dynamic-where` | khong bao | dat |
| tests/negative/php/sql_injection.php | 28 | `team.php.audit.query-single-dynamic-where` | khong bao | dat |
| tests/negative/php/sql_injection.php | 30 | `team.php.audit.query-single-dynamic-where` | khong bao | dat |
| tests/negative/php/sql_injection.php | 32 | `team.php.audit.query-single-dynamic-where` | khong bao | dat |
| tests/negative/php/sql_injection.php | 36 | `team.php.audit.query-single-dynamic-where` | khong bao | dat |
| tests/negative/php/sql_injection.php | 41 | `team.php.audit.query-single-dynamic-where` | khong bao | dat |
| tests/negative/php/sql_injection.php | 43 | `team.php.audit.query-single-dynamic-where` | khong bao | dat |
| tests/negative/php/sql_injection.php | 45 | `team.php.audit.query-single-dynamic-where` | khong bao | dat |
| tests/negative/php/xss.php | 5 | `team.php.xss-taint` | khong bao | dat |
| tests/negative/php/xss.php | 7 | `team.php.xss-taint` | khong bao | dat |
| tests/negative/php/xss.php | 13 | `team.php.audit.echo-unescaped` | khong bao | dat |
| tests/negative/php/xss.php | 15 | `team.php.audit.echo-unescaped` | khong bao | dat |
| tests/negative/php/xss.php | 17 | `team.php.audit.echo-unescaped` | khong bao | dat |
| tests/negative/php/xss.php | 23 | `team.php.xss-template-request` | khong bao | dat |
| tests/negative/php/xss.php | 23 | `team.php.audit.xss-template-echo` | khong bao | dat |
| tests/negative/php/xss.php | 25 | `team.php.xss-template-request` | khong bao | dat |
| tests/negative/php/xss.php | 27 | `team.php.audit.xss-template-echo` | khong bao | dat |
| tests/negative/php/xss.php | 29 | `team.php.audit.xss-template-echo` | khong bao | dat |
| tests/negative/php/xss.php | 34 | `team.php.xss-taint` | khong bao | dat |
| tests/negative/php/xss.php | 39 | `team.php.xss-taint` | khong bao | dat |
| tests/negative/php/xss.php | 43 | `team.php.xss-taint` | khong bao | dat |
| tests/negative/python/authentication_weakness.py | 8 | `team.authentication-weakness` | khong bao | dat |
| tests/negative/python/authentication_weakness.py | 10 | `team.auth-secret-equality` | khong bao | dat |
| tests/negative/python/authentication_weakness.py | 13 | `team.auth-secret-equality` | khong bao | dat |
| tests/negative/python/authentication_weakness.py | 16 | `team.auth-secret-equality` | khong bao | dat |
| tests/negative/python/authentication_weakness.py | 19 | `team.auth-weak-password-hash` | khong bao | dat |
| tests/negative/python/authentication_weakness.py | 26 | `team.auth-session-fixation` | khong bao | dat |
| tests/negative/python/hardcoded_credentials.py | 5 | `team.hardcoded-credentials` | khong bao | dat |
| tests/negative/python/hardcoded_credentials.py | 7 | `team.hardcoded-auth-header` | khong bao | dat |
| tests/negative/python/hardcoded_credentials.py | 9 | `team.hardcoded-auth-header` | khong bao | dat |
| tests/negative/python/hardcoded_credentials.py | 14 | `team.py.hardcoded-password-compare` | khong bao | dat |
| tests/negative/python/hardcoded_credentials.py | 17 | `team.py.hardcoded-password-compare` | khong bao | dat |
| tests/negative/python/hardcoded_credentials.py | 24 | `team.hardcoded-credentials` | khong bao | dat |
| tests/negative/python/hardcoded_credentials.py | 26 | `team.hardcoded-credentials` | khong bao | dat |
| tests/negative/python/hardcoded_credentials.py | 28 | `team.hardcoded-auth-header` | khong bao | dat |
| tests/negative/python/os_command_injection.py | 9 | `team.os-command-injection` | khong bao | dat |
| tests/negative/python/os_command_injection.py | 9 | `team.audit.process-api` | khong bao | dat |
| tests/negative/python/os_command_injection.py | 9 | `team.py.cmdi-taint` | khong bao | dat |
| tests/negative/python/os_command_injection.py | 11 | `team.os-command-injection` | khong bao | dat |
| tests/negative/python/os_command_injection.py | 13 | `team.os-command-string-building` | khong bao | dat |
| tests/negative/python/os_command_injection.py | 15 | `team.os-command-injection` | khong bao | dat |
| tests/negative/python/os_command_injection.py | 21 | `team.py.cmdi-taint` | khong bao | dat |
| tests/negative/python/os_command_injection.py | 27 | `team.py.cmdi-taint` | khong bao | dat |
| tests/negative/python/os_command_injection.py | 32 | `team.os-command-injection` | khong bao | dat |
| tests/negative/python/path_traversal.py | 7 | `team.path-traversal` | khong bao | dat |
| tests/negative/python/path_traversal.py | 7 | `team.path-request-taint` | khong bao | dat |
| tests/negative/python/path_traversal.py | 13 | `team.archive-extract-all` | khong bao | dat |
| tests/negative/python/path_traversal.py | 18 | `team.path-from-parameter` | khong bao | dat |
| tests/negative/python/path_traversal.py | 23 | `team.path-from-parameter` | khong bao | dat |
| tests/negative/python/path_traversal.py | 29 | `team.path-request-taint` | khong bao | dat |
| tests/negative/python/path_traversal.py | 34 | `team.path-from-parameter` | khong bao | dat |
| tests/negative/python/path_traversal.py | 40 | `team.py.audit.pathlib-api` | khong bao | dat |
| tests/negative/python/path_traversal.py | 42 | `team.py.audit.pathlib-api` | khong bao | dat |
| tests/negative/python/path_traversal.py | 49 | `team.path-traversal` | khong bao | dat |
| tests/negative/python/path_traversal.py | 51 | `team.path-traversal` | khong bao | dat |
| tests/negative/python/sql_injection.py | 6 | `team.sql-injection` | khong bao | dat |
| tests/negative/python/sql_injection.py | 6 | `team.sql-string-building` | khong bao | dat |
| tests/negative/python/sql_injection.py | 6 | `team.audit.sql-api` | khong bao | dat |
| tests/negative/python/sql_injection.py | 8 | `team.sql-string-building` | khong bao | dat |
| tests/negative/python/sql_injection.py | 10 | `team.audit.sql-api` | khong bao | dat |
| tests/negative/python/sql_injection.py | 17 | `team.py.sqli-taint` | khong bao | dat |
| tests/negative/python/sql_injection.py | 17 | `team.sql-injection` | khong bao | dat |
| tests/negative/python/sql_injection.py | 20 | `team.py.sqli-taint` | khong bao | dat |
| tests/negative/python/sql_injection.py | 26 | `team.sql-injection` | khong bao | dat |
| tests/negative/python/sql_injection.py | 28 | `team.sql-injection` | khong bao | dat |
| tests/negative/python/sql_injection.py | 30 | `team.sql-injection` | khong bao | dat |
| tests/negative/python/xss.py | 9 | `team.py.xss-taint` | khong bao | dat |
| tests/negative/python/xss.py | 9 | `team.audit.html-output-api` | khong bao | dat |
| tests/negative/python/xss.py | 15 | `team.py.xss-taint` | khong bao | dat |
| tests/negative/python/xss.py | 20 | `team.xss-unsafe-html` | khong bao | dat |
| tests/negative/python/xss.py | 22 | `team.xss-unsafe-html` | khong bao | dat |
| tests/negative/python/xss.py | 24 | `team.xss-html-string-building` | khong bao | dat |
| tests/negative/python/xss.py | 26 | `team.audit.html-output-api` | khong bao | dat |
| tests/negative/python/xss.py | 26 | `team.xss-response-formatting` | khong bao | dat |
| tests/negative/python/xss.py | 32 | `team.py.xss-jinja-autoescape-default` | khong bao | dat |
| tests/negative/python/xss.py | 34 | `team.py.audit.response-body` | khong bao | dat |
| tests/positive/java/authentication_weakness.java | 11 | `team.java.auth-jwt-unverified` | bao | dat |
| tests/positive/java/authentication_weakness.java | 17 | `team.java.auth-weak-password-hash` | bao | dat |
| tests/positive/java/hardcoded_credentials.java | 10 | `team.java.hardcoded-secret` | bao | dat |
| tests/positive/java/hardcoded_credentials.java | 14 | `team.java.hardcoded-secret` | bao | dat |
| tests/positive/java/hardcoded_credentials.java | 19 | `team.java.hardcoded-password-compare` | bao | dat |
| tests/positive/java/os_command_injection.java | 12 | `team.java.cmdi-taint` | bao | dat |
| tests/positive/java/os_command_injection.java | 12 | `team.java.cmd-string` | bao | dat |
| tests/positive/java/os_command_injection.java | 17 | `team.java.audit.process-api` | bao | dat |
| tests/positive/java/os_command_injection.java | 25 | `team.java.audit.commandline-api` | bao | dat |
| tests/positive/java/os_command_injection.java | 27 | `team.java.audit.commandline-api` | bao | dat |
| tests/positive/java/path_traversal.java | 12 | `team.java.path-taint` | bao | dat |
| tests/positive/java/path_traversal.java | 12 | `team.java.audit.file-path-api` | bao | dat |
| tests/positive/java/path_traversal.java | 17 | `team.java.path-upload-name` | bao | dat |
| tests/positive/java/path_traversal.java | 17 | `team.java.audit.file-path-api` | bao | dat |
| tests/positive/java/path_traversal.java | 22 | `team.java.audit.file-path-api` | bao | dat |
| tests/positive/java/sql_injection.java | 13 | `team.java.sqli-taint` | bao | dat |
| tests/positive/java/sql_injection.java | 13 | `team.java.sqli-concat` | bao | dat |
| tests/positive/java/sql_injection.java | 13 | `team.java.audit.sql-api` | bao | dat |
| tests/positive/java/sql_injection.java | 18 | `team.java.sqli-taint` | bao | dat |
| tests/positive/java/sql_injection.java | 18 | `team.java.sqli-concat` | bao | dat |
| tests/positive/java/sql_injection.java | 23 | `team.java.audit.sql-api` | bao | dat |
| tests/positive/java/xss.java | 12 | `team.java.xss-taint` | bao | dat |
| tests/positive/java/xss.java | 12 | `team.java.xss-html-concat` | bao | dat |
| tests/positive/java/xss.java | 12 | `team.java.audit.response-output` | bao | dat |
| tests/positive/java/xss.java | 17 | `team.java.audit.response-output` | bao | dat |
| tests/positive/java/xss.java | 25 | `team.java.xss-writer-output` | bao | dat |
| tests/positive/java/xss.java | 27 | `team.java.xss-writer-output` | bao | dat |
| tests/positive/java/xss.java | 29 | `team.java.xss-writer-output` | bao | dat |
| tests/positive/javascript/authentication_weakness.js | 11 | `team.js.auth-jwt-unverified` | bao | dat |
| tests/positive/javascript/authentication_weakness.js | 13 | `team.js.auth-jwt-decode` | bao | dat |
| tests/positive/javascript/authentication_weakness.js | 15 | `team.js.auth-weak-password-hash` | bao | dat |
| tests/positive/javascript/hardcoded_credentials.js | 10 | `team.js.hardcoded-secret` | bao | dat |
| tests/positive/javascript/hardcoded_credentials.js | 12 | `team.js.hardcoded-secret` | bao | dat |
| tests/positive/javascript/hardcoded_credentials.js | 14 | `team.js.hardcoded-secret` | bao | dat |
| tests/positive/javascript/hardcoded_credentials.js | 18 | `team.js.hardcoded-password-compare` | bao | dat |
| tests/positive/javascript/os_command_injection.js | 11 | `team.js.cmdi-taint` | bao | dat |
| tests/positive/javascript/os_command_injection.js | 11 | `team.js.cmd-shell` | bao | dat |
| tests/positive/javascript/os_command_injection.js | 17 | `team.js.audit.process-api` | bao | dat |
| tests/positive/javascript/os_command_injection.js | 19 | `team.js.audit.process-api` | bao | dat |
| tests/positive/javascript/path_traversal.js | 11 | `team.js.path-taint` | bao | dat |
| tests/positive/javascript/path_traversal.js | 13 | `team.js.path-taint` | bao | dat |
| tests/positive/javascript/path_traversal.js | 19 | `team.js.audit.fs-path-api` | bao | dat |
| tests/positive/javascript/path_traversal.js | 21 | `team.js.audit.fs-path-api` | bao | dat |
| tests/positive/javascript/path_traversal.js | 23 | `team.js.audit.fs-path-api` | bao | dat |
| tests/positive/javascript/sql_injection.js | 12 | `team.js.sqli-taint` | bao | dat |
| tests/positive/javascript/sql_injection.js | 12 | `team.js.sqli-string` | bao | dat |
| tests/positive/javascript/sql_injection.js | 14 | `team.js.sqli-string` | bao | dat |
| tests/positive/javascript/sql_injection.js | 20 | `team.js.sqli-dynamic-query` | bao | dat |
| tests/positive/javascript/sql_injection.js | 22 | `team.js.sqli-dynamic-query` | bao | dat |
| tests/positive/javascript/sql_injection.js | 24 | `team.js.sqli-dynamic-query` | bao | dat |
| tests/positive/javascript/sql_injection.js | 29 | `team.js.audit.sql-api` | bao | dat |
| tests/positive/javascript/xss.js | 11 | `team.js.xss-taint` | bao | dat |
| tests/positive/javascript/xss.js | 11 | `team.js.xss-html-concat` | bao | dat |
| tests/positive/javascript/xss.js | 16 | `team.js.xss-dom-sink` | bao | dat |
| tests/positive/javascript/xss.js | 22 | `team.js.xss-jquery-insert` | bao | dat |
| tests/positive/javascript/xss.js | 24 | `team.js.xss-jquery-insert` | bao | dat |
| tests/positive/php/authentication_weakness.php | 5 | `team.php.auth-weak-password-hash` | bao | dat |
| tests/positive/php/hardcoded_credentials.php | 3 | `team.php.hardcoded-secret` | bao | dat |
| tests/positive/php/hardcoded_credentials.php | 5 | `team.php.hardcoded-secret` | bao | dat |
| tests/positive/php/hardcoded_credentials.php | 7 | `team.php.hardcoded-secret` | bao | dat |
| tests/positive/php/hardcoded_credentials.php | 9 | `team.php.hardcoded-secret` | bao | dat |
| tests/positive/php/hardcoded_credentials.php | 13 | `team.php.hardcoded-password-compare` | bao | dat |
| tests/positive/php/os_command_injection.php | 5 | `team.php.cmdi-taint` | bao | dat |
| tests/positive/php/os_command_injection.php | 5 | `team.php.cmd-dynamic` | bao | dat |
| tests/positive/php/os_command_injection.php | 11 | `team.php.audit.process-api` | bao | dat |
| tests/positive/php/os_command_injection.php | 13 | `team.php.audit.process-api` | bao | dat |
| tests/positive/php/os_command_injection.php | 22 | `team.php.audit.gitphp-unescaped-argument` | bao | dat |
| tests/positive/php/os_command_injection.php | 29 | `team.php.audit.gitphp-unescaped-argument` | bao | dat |
| tests/positive/php/os_command_injection.php | 35 | `team.php.audit.gitphp-unescaped-argument` | bao | dat |
| tests/positive/php/path_traversal.php | 5 | `team.php.path-taint` | bao | dat |
| tests/positive/php/sql_injection.php | 5 | `team.php.sqli-taint` | bao | dat |
| tests/positive/php/sql_injection.php | 5 | `team.php.sqli-string` | bao | dat |
| tests/positive/php/sql_injection.php | 8 | `team.php.sqli-string` | bao | dat |
| tests/positive/php/sql_injection.php | 14 | `team.php.audit.sql-api` | bao | dat |
| tests/positive/php/sql_injection.php | 16 | `team.php.audit.sql-api` | bao | dat |
| tests/positive/php/sql_injection.php | 18 | `team.php.audit.sql-api` | bao | dat |
| tests/positive/php/sql_injection.php | 24 | `team.php.audit.query-single-dynamic-where` | bao | dat |
| tests/positive/php/sql_injection.php | 26 | `team.php.audit.query-single-dynamic-where` | bao | dat |
| tests/positive/php/sql_injection.php | 29 | `team.php.audit.query-single-dynamic-where` | bao | dat |
| tests/positive/php/sql_injection.php | 34 | `team.php.audit.query-single-dynamic-where` | bao | dat |
| tests/positive/php/sql_injection.php | 40 | `team.php.audit.query-single-dynamic-where` | bao | dat |
| tests/positive/php/xss.php | 5 | `team.php.xss-taint` | bao | dat |
| tests/positive/php/xss.php | 11 | `team.php.audit.echo-unescaped` | bao | dat |
| tests/positive/php/xss.php | 13 | `team.php.audit.echo-unescaped` | bao | dat |
| tests/positive/php/xss.php | 19 | `team.php.xss-template-request` | bao | dat |
| tests/positive/php/xss.php | 21 | `team.php.xss-template-request` | bao | dat |
| tests/positive/php/xss.php | 23 | `team.php.xss-template-request` | bao | dat |
| tests/positive/php/xss.php | 25 | `team.php.audit.xss-template-echo` | bao | dat |
| tests/positive/php/xss.php | 27 | `team.php.audit.xss-template-echo` | bao | dat |
| tests/positive/python/authentication_weakness.py | 7 | `team.authentication-weakness` | bao | dat |
| tests/positive/python/authentication_weakness.py | 9 | `team.auth-secret-equality` | bao | dat |
| tests/positive/python/authentication_weakness.py | 12 | `team.auth-weak-password-hash` | bao | dat |
| tests/positive/python/authentication_weakness.py | 18 | `team.auth-session-fixation` | bao | dat |
| tests/positive/python/hardcoded_credentials.py | 4 | `team.hardcoded-credentials` | bao | dat |
| tests/positive/python/hardcoded_credentials.py | 6 | `team.hardcoded-credentials` | bao | dat |
| tests/positive/python/hardcoded_credentials.py | 8 | `team.hardcoded-auth-header` | bao | dat |
| tests/positive/python/hardcoded_credentials.py | 10 | `team.hardcoded-auth-header` | bao | dat |
| tests/positive/python/hardcoded_credentials.py | 15 | `team.py.hardcoded-password-compare` | bao | dat |
| tests/positive/python/hardcoded_credentials.py | 22 | `team.hardcoded-credentials` | bao | dat |
| tests/positive/python/hardcoded_credentials.py | 24 | `team.hardcoded-credentials` | bao | dat |
| tests/positive/python/hardcoded_credentials.py | 29 | `team.hardcoded-credentials` | bao | dat |
| tests/positive/python/hardcoded_credentials.py | 33 | `team.hardcoded-auth-header` | bao | dat |
| tests/positive/python/os_command_injection.py | 8 | `team.os-command-injection` | bao | dat |
| tests/positive/python/os_command_injection.py | 8 | `team.audit.process-api` | bao | dat |
| tests/positive/python/os_command_injection.py | 10 | `team.os-command-injection` | bao | dat |
| tests/positive/python/os_command_injection.py | 10 | `team.audit.process-api` | bao | dat |
| tests/positive/python/os_command_injection.py | 12 | `team.os-command-injection` | bao | dat |
| tests/positive/python/os_command_injection.py | 14 | `team.os-command-string-building` | bao | dat |
| tests/positive/python/os_command_injection.py | 14 | `team.audit.process-api` | bao | dat |
| tests/positive/python/os_command_injection.py | 20 | `team.py.cmdi-taint` | bao | dat |
| tests/positive/python/os_command_injection.py | 20 | `team.os-command-injection` | bao | dat |
| tests/positive/python/path_traversal.py | 7 | `team.path-traversal` | bao | dat |
| tests/positive/python/path_traversal.py | 7 | `team.path-request-taint` | bao | dat |
| tests/positive/python/path_traversal.py | 13 | `team.archive-extract-all` | bao | dat |
| tests/positive/python/path_traversal.py | 18 | `team.path-from-parameter` | bao | dat |
| tests/positive/python/path_traversal.py | 24 | `team.path-request-taint` | bao | dat |
| tests/positive/python/path_traversal.py | 30 | `team.py.audit.pathlib-api` | bao | dat |
| tests/positive/python/path_traversal.py | 32 | `team.py.audit.pathlib-api` | bao | dat |
| tests/positive/python/path_traversal.py | 39 | `team.path-traversal` | bao | dat |
| tests/positive/python/path_traversal.py | 44 | `team.path-traversal` | bao | dat |
| tests/positive/python/sql_injection.py | 6 | `team.sql-injection` | bao | dat |
| tests/positive/python/sql_injection.py | 6 | `team.sql-string-building` | bao | dat |
| tests/positive/python/sql_injection.py | 8 | `team.sql-string-building` | bao | dat |
| tests/positive/python/sql_injection.py | 10 | `team.sql-string-building` | bao | dat |
| tests/positive/python/sql_injection.py | 12 | `team.audit.sql-api` | bao | dat |
| tests/positive/python/sql_injection.py | 19 | `team.py.sqli-taint` | bao | dat |
| tests/positive/python/sql_injection.py | 25 | `team.sql-injection` | bao | dat |
| tests/positive/python/sql_injection.py | 27 | `team.sql-injection` | bao | dat |
| tests/positive/python/sql_injection.py | 29 | `team.sql-injection` | bao | dat |
| tests/positive/python/sql_injection.py | 31 | `team.sql-injection` | bao | dat |
| tests/positive/python/xss.py | 7 | `team.xss-unsafe-html` | bao | dat |
| tests/positive/python/xss.py | 9 | `team.xss-html-string-building` | bao | dat |
| tests/positive/python/xss.py | 11 | `team.xss-html-string-building` | bao | dat |
| tests/positive/python/xss.py | 13 | `team.xss-unsafe-html` | bao | dat |
| tests/positive/python/xss.py | 15 | `team.audit.html-output-api` | bao | dat |
| tests/positive/python/xss.py | 20 | `team.xss-response-formatting` | bao | dat |
| tests/positive/python/xss.py | 26 | `team.py.xss-taint` | bao | dat |
| tests/positive/python/xss.py | 26 | `team.xss-response-formatting` | bao | dat |
| tests/positive/python/xss.py | 32 | `team.py.xss-jinja-autoescape-default` | bao | dat |
| tests/positive/python/xss.py | 34 | `team.py.audit.response-body` | bao | dat |
