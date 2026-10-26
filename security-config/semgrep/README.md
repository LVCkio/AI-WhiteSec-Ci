# Bộ rule Semgrep CE của AI-WhiteSec-CI (ruleset v4.6.0)

## Xử lý chất lượng ngày 26/10/2026 — task 1 và 2

79 rule đang bật; Semgrep 1.181.0; **287/287 regression cases đạt**, manifest đã xác minh. Bốn rule audit rộng không đạt TC3/TC4 trên train đã chuyển sang `rules_disabled/`; nguồn và fixture cũ được giữ để khôi phục. Hai rule PHP bổ sung ở v4.5.0 tiếp tục hoạt động ở tầng audit.

Đã rà kỹ thuật 11 mẫu cần xem lại, đối chiếu cả mã upstream đúng phiên bản. Có bốn ca chưa xác nhận SQLi tại finding, sáu ca HOLD và một ca đề xuất cách ly khi xây release dữ liệu đã duyệt. Không tự đổi nhãn gốc hoặc ghi nhận AI là người duyệt.

Xem `reports/task12_v22_2026-10-26/README.md`: số đo trước/sau, độ phủ đánh đổi và bảng ký duyệt 11 mẫu. Bản nguồn trước thay đổi: `archive/semgrep_v4.5.0_before_task12_2026-10-26.zip`.

## Lịch sử v4.5.0 — bổ sung ngày 26/10/2026 trên train v2.2

83 rule; Semgrep 1.181.0; 299/299 regression cases đạt. Hai rule mới đều ở tầng `audit`:

- `team.php.audit.query-single-dynamic-where`: kiểm tra WHERE động trong API `query_single`; bỏ qua literal, placeholder có bindings và biểu thức chỉ nối số qua `intval`/ép kiểu.
- `team.php.audit.gitphp-unescaped-argument`: trỏ tới dòng thêm giá trị động chưa quote vào danh sách tham số của executor GitPHP `Execute(..., GIT_*, args)`; bỏ qua quote tại chỗ, số nguyên và danh sách bị thay thế trước khi gọi.

Bằng chứng phát triển lấy từ train và các cặp trước/sau sửa; validation chỉ để đo. Xem `reports/r4_v22_2026-10-26/README.md` và hàng chờ review nhãn ở cùng thư mục. Không dùng rule mới để tự động đổi nhãn hoặc tự chặn build. Không dùng test hay bốn ứng dụng mục tiêu trong vòng bổ sung này.

Bản nguồn v4.4.1 đã lưu ở `archive/semgrep_v4.4.1_before_r4_2026-10-26.zip`. Các mục lịch sử bên dưới mô tả những lần xây dựng trước.

Thư mục này là **nguồn chính thức** của custom rule Semgrep cho luồng SAST. Luồng SAST chạy **độc lập, song song** với CodeBERT; hai luồng chỉ gặp nhau ở bước so sánh và Security Gate.

## Cấu trúc

```
security-config/semgrep/
├── rules/                     # nguồn: 1 file cho mỗi ngôn ngữ × lớp lỗ hổng
│   ├── python/  java/  javascript/  php/
│   │   └── sql_injection.yml, xss.yml, os_command_injection.yml,
│   │       path_traversal.yml, authentication_weakness.yml, hardcoded_credentials.yml
├── rules_disabled/            # rule đã tắt (không vào bundle), lý do ở metadata.disabled_v42
├── TIEU_CHI_CHON_RULE.md      # tiêu chí TC1–TC8 chọn/lọc rule, quyết định v4.2.0 và số liệu
├── tests/
│   ├── positive/<ngôn ngữ>/<lớp>.*   # code có lỗ hổng: rule PHẢI báo   (chú thích  ruleid: <id>)
│   └── negative/<ngôn ngữ>/<lớp>.*   # code an toàn:   rule KHÔNG được báo (chú thích  ok: <id>)
├── tools/ruleset.py           # kiểm tra chuẩn rule, chạy test, tạo bundle + manifest, verify trong CI
├── reports/                   # kết quả lần kiểm tra gần nhất (rule_test_report.md, rule_test_results.json)
├── semgrep.yml                # bundle sinh tự động từ rules/ — file dùng cho lần quét chính thức
├── .semgrepignore             # thư mục/tệp không quét trong repo ứng dụng
├── ruleset-manifest.json      # phiên bản, SHA-256, phiên bản Semgrep/Bandit, kết quả regression
└── run_rule_tests.bat         # chạy toàn bộ kiểm tra trên Windows bằng .venv của dự án
```

## Một rule được xem là đạt chuẩn khi

1. **Đủ thông tin:** `id`, `languages`, `severity` (của Semgrep), `message`, và trong `metadata`: `cwe`, `owasp`, `vuln_class`, `confidence` (`high`/`audit`), `severity` (critical/high/medium/low), `scope` (phạm vi áp dụng: ngôn ngữ, framework), `rule_version`, `ruleset_version`.
2. **Có positive test:** ít nhất một đoạn code có lỗ hổng mà rule phải báo.
3. **Có negative test:** ít nhất một đoạn code an toàn mà rule không được báo (đã làm sạch, hằng số, API an toàn).
4. **Đo trên dữ liệu có ground truth:** precision/recall trên tập val (không dùng test) và trên 4 ứng dụng mục tiêu (DVWA, WebGoat, Juice Shop, ShopNotes).
5. **Khóa phiên bản:** `ruleset-manifest.json` ghi `ruleset_version`, `ruleset_commit`, `ruleset_sha256`, `semgrep_version`.

`tools/ruleset.py check` tự kiểm tra (1)–(3) về mặt cấu trúc; `tools/ruleset.py all` chạy Semgrep trên mọi test và ghi manifest.

## Cách viết rule (source – sink – sanitizer)

- **Source:** dữ liệu không tin cậy (`request.args`, `$_GET`, `req.query`, `request.getParameter(...)`).
- **Sink:** hàm nguy hiểm (`os.system`, `mysqli_query`, `res.send`, `new File(...)`).
- **Sanitizer:** hàm làm sạch (`shlex.quote`, `htmlspecialchars`, `Integer.parseInt`…). Quy ước chung của dự án: hàm có tên bắt đầu bằng `validate`, `sanitize`, `escape`, `clean`, `is_valid` được coi là sanitizer: giá trị trả về của hàm là dữ liệu sạch (ví dụ `host = validate_host(request.args["host"])`). Kiểu kiểm tra `if validate_host(host): ...` không được Semgrep CE coi là làm sạch biến `host`, nên hàm kiểm tra nên trả về giá trị đã xác minh.
- **Khi nào cảnh báo:**
  - `high`: dữ liệu từ source tới sink mà không qua sanitizer (rule taint), hoặc mẫu code gần như chắc chắn sai (tắt kiểm tra chữ ký JWT, mật khẩu viết cứng).
  - `audit`: dùng API nguy hiểm với giá trị không phải hằng số; cần rà soát, không tự kết luận.
- Ví dụ: `os.system("service nginx restart")` **không** bị báo (lệnh là hằng số), còn `os.system("ping " + request.args["host"])` bị báo `high`.

## Thay đổi trong v4 so với v3 (`rules/custom/`)

| Thay đổi | Lý do (số liệu train v5, rule v3) |
|---|---|
| Thêm 3 rule taint Python: `team.py.sqli-taint`, `team.py.xss-taint`, `team.py.cmdi-taint` | Python trước chỉ có taint cho Path traversal |
| Thêm 4 rule `*.hardcoded-password-compare` (so sánh mật khẩu với chuỗi hằng) | Các mẫu HARDCODED dạng `"Secret".equals(password)` trước bị rule Auth bắt nhầm lớp |
| `team.os-command-injection`, `team.audit.process-api`, `team.java.audit.process-api`: bỏ lệnh là hằng chuỗi | Đúng ví dụ của nhóm (`os.system("service nginx restart")`) |
| Siết rule so sánh bí mật (`*.auth-secret-equality`, `team.java.auth-secret-equals`): chỉ xét biến, bỏ so sánh với hằng/true/false/null | Precision lớp v3: PHP 1/20, JS 0/5, Java 0/5 |
| `team.java.auth-weak-password-hash`: chỉ báo khi giá trị băm là mật khẩu | v3 báo mọi MD5: 0/4 |
| `team.php.auth-weak-password-hash`: tên biến phải là từ chỉ mật khẩu | v3: 1/5 |
| `team.audit.html-output-api`: `self.write` thay cho `$SELF.write` | v3 bắt nhầm `f.write` ghi file: 19/40 |
| `team.audit.sql-api`: chỉ đối tượng giống DB, bỏ câu truy vấn hằng | v3: 17/29 |
| Mỗi rule có thêm `severity`, `scope`, `rule_version`, `ruleset_version`; OWASP CWE-916 sửa thành A02:2021 | Theo tiêu chí metadata |

ID rule cũ được giữ nguyên để so sánh được với kết quả trước. Bộ v3 vẫn ở `rules/custom/` (đóng băng) vì các kết quả T07/R03/R05 đã báo cáo dùng bộ đó.

## Bổ sung trong v4.1.0 (chỉ thêm rule, giữ nguyên khuôn mẫu)

15 rule mới (tổng 84), tất cả ở tầng `audit`, chèn vào đúng file `rules/<ngôn ngữ>/<lớp>.yml`, mỗi rule có positive/negative test. Không sửa rule v4.0 nào (chỉ cập nhật `ruleset_version`). Rule được chọn từ phân tích mẫu bị bỏ sót trên **train v5** và chỉnh bằng train; val chỉ dùng để đánh giá. Bản v4.0 lưu ở `archive/semgrep_v4.0.0.yml`; nguồn bổ sung ban đầu ở `archive/additions_v4.1.0/`.

| Ngôn ngữ | Rule mới | Bắt gì |
|---|---|---|
| JavaScript | `team.js.xss-jquery-insert` | `append/prepend/after/before/replaceWith` của jQuery/DOM với giá trị không phải hằng |
| JavaScript | `team.js.sqli-dynamic-query`, `team.js.audit.sql-api` | truy vấn DB ghép chuỗi/template; API truy vấn nhận biến |
| JavaScript | `team.js.audit.fs-path-api` | `fs.*`, `res.sendFile/download` nhận đường dẫn động |
| JavaScript | `team.js.audit.process-api` | `child_process.exec/spawn/...` với lệnh động |
| PHP | `team.php.audit.echo-unescaped` | `echo`/`print` biến không qua hàm escape |
| PHP | `team.php.audit.sql-api` | `$wpdb->get_results`, `->query`, Zend `->where/->execute`… nhận truy vấn động |
| PHP | `team.php.audit.file-path-api` | `fopen`, `file_get_contents`, `unlink`, `move_uploaded_file`… nhận đường dẫn động |
| PHP | `team.php.audit.process-api` | `exec/system/popen/proc_open/escapeshellcmd` với lệnh động |
| PHP | `team.php.audit.auth-code` | hàm login/kiểm tra quyền, ghi user vào `$_SESSION` |
| Java | `team.java.xss-writer-output` | ghi ra printer/writer HTML-XML, Jsoup `Element.html()` |
| Java | `team.java.audit.commandline-api` | `CommandLine` (Apache Commons Exec) dựng từ giá trị động |
| Python | `team.py.audit.pathlib-api` | `Path()`, `shutil.move`, `os.rename`, `tarfile/zipfile.open` với đường dẫn động |
| Python | `team.py.xss-jinja-autoescape-default` | `jinja2.Environment/Template` không bật autoescape |
| Python | `team.py.audit.response-body` | `flask.Response`/`web.Response` với nội dung động |

Kết quả trên **val v5** (693 mẫu, chỉ custom rule, `21_rule_metrics.py`): recall (có ≥ 1 finding đúng lớp) v3 0,211 → v4.0 0,202 → **v4.1 0,270**; tỉ lệ finding đúng lớp 0,841 → 0,869 → 0,821. Chi tiết: `reports/rule_metrics_v41_val.md`, `reports/rule_metrics_v41_train.md`.

## Chạy

```powershell
# từ thư mục main/
.\.venv\Scripts\python.exe security-config\semgrep\tools\ruleset.py all      # kiểm tra + test + manifest
.\.venv\Scripts\python.exe security-config\semgrep\tools\ruleset.py verify   # trong CI, trước lần quét chính thức
.\.venv\Scripts\python.exe 03_run_sast.py --rules security-config\semgrep\semgrep.yml --baseline-config rules\registry_snapshot\p_python.yml rules\registry_snapshot\p_security-audit.yml
```

Hoặc nhấp đúp `run_rule_tests.bat`.

## Tự chủ và vận hành

1. Semgrep CE và Bandit được ghim phiên bản (`ci/requirements-ci.txt`: semgrep==1.181.0, bandit==1.9.4) và đóng gói trong Docker image `ci/Dockerfile`; nên lưu image này trong kho nội bộ.
2. Custom rule nằm trong repo dự án (thư mục này); rule có sẵn của Registry dùng bản chụp `rules/registry_snapshot/`.
3. Lần quét chính thức **không tải rule mới** từ Registry: luôn dùng `semgrep.yml` + bản chụp, cùng `--metrics=off`.
4. Mọi thay đổi rule hoặc nâng cấp Semgrep chỉ được dùng sau khi `ruleset.py all` báo `regression_passed: true`; CI chạy `ruleset.py verify` trước khi quét.
5. Nếu Semgrep không chạy được, pipeline chuyển sang chế độ suy giảm **chỉ CodeBERT** và ghi rõ trong báo cáo (việc cần làm trong `scan.py`).

## Thay đổi trong v4.2.0 (84 → 81 rule)

Áp dụng tiêu chí TC1–TC8 trong `TIEU_CHI_CHON_RULE.md` (dựa trên phương pháp viết rule của Semgrep):
thêm 2 rule PHP template dạng `regex` (`team.php.xss-template-request` high, `team.php.audit.xss-template-echo`
audit), sửa 4 rule có báo nhầm xác định được nguyên nhân (`team.java.sqli-taint`, `team.js.hardcoded-password-compare`,
`team.js.audit.fs-path-api`, `team.audit.auth-code`), tắt 5 rule không đạt ngưỡng (chuyển sang `rules_disabled/`).
`tools/ruleset.py check` chấp nhận rule `languages: [regex]` khi `paths.include` giới hạn đúng đuôi file của thư mục.
Đo bằng `run_v42.bat` (thêm `30_rule_pairs_diff.py` cho TC5: phân biệt bản lỗi / bản đã vá).
