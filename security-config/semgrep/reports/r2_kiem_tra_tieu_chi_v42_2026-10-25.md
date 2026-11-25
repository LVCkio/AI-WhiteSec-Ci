# R2 · Kiểm tra 81 rule v4.2.0 theo semgrep_tool.md và TIEU_CHI_CHON_RULE.md

- Ngày: 2026-10-25. Tài liệu chuẩn: `docs/semgrep_tool.md` v1.2, `docs/taxonomy.yml` v0.3.0, `security-config/semgrep/TIEU_CHI_CHON_RULE.md` (TC1–TC8).
- Ruleset được kiểm: **v4.2.0**, 81 rule, bundle sha256 `95267dec1cbd566c88240c58d42ec4e61ef3d503b8904a204ab29cdb8da381f3`, Semgrep ghim 1.181.0 (manifest 2026-10-21; 270/270 test).
- Số liệu TC4/TC5 lấy từ báo cáo đã có, đo trên **dữ liệu cũ**: `six_class_v5_1_e03` train (sha256 `fcdc9b2a…eca060`) / val (`a28dc9cb…5452ac5`) và cặp `a01_pairs_v51` (`reports/rule_metrics_v42_{train,val}.csv`, `reports/rule_pairs_diff_v42_{train,val}.csv`). **Chưa đo trên dataset v2.2** (không có trong workspace) — theo mục 8.1 các số này phải đo lại trước khi dựa vào.
- Lệnh đã chạy: kiểm tra tĩnh nội dung rule + đọc báo cáo test/số liệu có sẵn; `python security-config/semgrep/tools/ruleset.py check` (không cần Semgrep). **Chưa chạy `ruleset.py all` / `verify`** vì máy làm việc không có Semgrep 1.181.0 — người dùng chạy `run_ruleset_v43.bat` trên máy có `.venv`.
- Không đọc/quét tập test và 4 ứng dụng mục tiêu; không dùng kết quả CodeBERT; không sửa dataset, `models/gate_config.json`.

## 1. Tổng hợp theo tiêu chí

| Tiêu chí | Đạt | Không đạt | Xử lý |
|---|---:|---:|---|
| TC7 metadata đủ 8 trường | 81 | 0 | — |
| TC7 ≥ 1 test positive + ≥ 1 negative, tất cả đạt | 81 | 0 | — |
| 5.3 severity Semgrep suy từ confidence (high→ERROR, audit→WARNING) | 52 | 29 | Đã sửa 29 rule, tăng rule_version |
| 5.3 metadata.severity suy từ lớp (taxonomy) | 81 | 0 | — |
| TC1/mục 3 tên lớp theo taxonomy.yml | 69 | 12 | Chờ quyết định đổi tên AUTHENTICATION_WEAKNESS → INSECURE_AUTHENTICATION (một đợt riêng) |
| TC1 CWE thuộc danh sách của lớp | 76 | 5 | CWE-916 (4 rule) chờ xác nhận; CWE-384 (1 rule) ngoài taxonomy |
| 5.2 taint → high | 80 | 1 | team.path-from-parameter (source là tham số hàm, giữ audit làm ngoại lệ) |
| 5.2 pattern-regex chỉ khi parser không đọc được, kèm paths.include | 68 | 13 | Rule regex cũ (Python v3 + 5 rule Java/JS/PHP): cần viết lại bằng AST và đo trên train |
| 5.2 audit chỉ khớp giá trị động (pattern-not hằng chuỗi) | 81 | 0 | 5 rule không có pattern-not nhưng mẫu chỉ khớp giá trị động/ API nguy hiểm tự thân (đạt về ý nghĩa) |
| TC4 ngưỡng đúng lớp (≥ 5 lần báo; train v5 legacy) | 79 | 2 | team.php.path-taint hạ audit; team.js.audit.fs-path-api val 2/9: ứng viên tắt, chờ đo v2.2 |
| TC5 cặp lỗi/vá (train v5 + a01, legacy) | 66 | 15 | 14 rule audit báo bản vá nhiều hơn bản lỗi: không đổi ngưỡng; chờ đo theo dòng bị sửa (mục 5.4 [Mở]) |

Kết quả: trước khi sửa, **24/81** rule không vướng tiêu chí nào. Sau đợt sửa: **32 rule đạt hết**, **12 rule đã sửa xong**, **37 rule còn tồn tại** việc cần quyết định hoặc cần đo lại trên v2.2 (mục 3). `ruleset.py check` cho v4.3.0: 0 lỗi chặn phát hành, 32 cảnh báo.

## 2. Đã bổ sung / sửa trong đợt này (ruleset v4.3.0)

1. **Severity theo confidence (mục 5.3)**: 29 rule sửa `severity` (INFO→WARNING cho 20 rule audit; WARNING→ERROR cho 9 rule high, gồm `team.sql-injection`, `team.hardcoded-credentials` nêu ở mục 9). Kiểm tra trước: gate và báo cáo chỉ dùng `metadata.confidence`, không dùng `severity` của Semgrep (`03_run_sast.py::finding_confidence`), nên quyết định Gate không đổi.
2. **`team.php.path-taint` hạ high → audit** (mục 9, TC4: train 7/13 = 0,54 < 0,80, vẫn ≥ 0,50). Ghi ngoại lệ: rớt TC5-audit (bản vá 10 > bản lỗi 7) nhưng là rule PHP PATH_TRAVERSAL gần như duy nhất còn lại. Lưu ý: quyết định này thay cho quyết định giữ high ngày 21/10; Gate sẽ chuyển các finding loại này từ BLOCK sang REVIEW khi quét lại.
3. Mọi rule sửa đều tăng `rule_version` (X.Y.0 → X.(Y+1).0) và có ghi chú `change_v43`; toàn bộ 81 rule chuyển `ruleset_version: 4.3.0`; `tools/ruleset.py` đổi `RULESET_VERSION = 4.3.0`.
4. **`tools/ruleset.py check` thêm kiểm tra theo tài liệu mới**: lỗi (chặn phát hành) khi severity lệch confidence, metadata.severity lệch lớp, lớp không có trong taxonomy; cảnh báo khi dùng tên lớp cũ, CWE ngoài danh sách lớp, taint ở tầng audit, pattern-regex không có `paths.include`. Manifest ghi `taxonomy_version` + sha256; **bỏ Bandit** khỏi manifest và báo cáo (điều 1).
5. Chép `docs/taxonomy.yml` và `docs/semgrep_tool.md` vào `main/docs/` (tài liệu tham chiếu đường dẫn này).
6. Bản v4.2.0 lưu ở `archive/semgrep_v4.2.0.yml`, `archive/ruleset-manifest_v4.2.0.json`, `archive/rules_v4.2.0/` (không xóa).

## 3. Còn tồn tại — cần trưởng nhóm quyết định hoặc cần dữ liệu v2.2

| Việc | Rule | Vì sao chưa làm |
|---|---|---|
| Đổi tên lớp Auth sang `INSECURE_AUTHENTICATION` | 12 rule Auth | Mục 9 yêu cầu làm trong một đợt riêng, đồng thời sửa `03_run_sast.py` và mọi chỗ so tên lớp. Mô hình C03 hiện tại vẫn trả nhãn `AUTHENTICATION_WEAKNESS`, đổi riêng phía rule sẽ làm Compare coi hai luồng là khác lớp. |
| CWE-916 (băm mật khẩu yếu) | 4 rule `*.auth-weak-password-hash` | taxonomy `open_questions`: chờ bảng gán nhãn v2.2 |
| CWE-384 (session fixation) ngoài taxonomy | `team.auth-session-fixation` | TC1: CWE không thuộc [287, 306, 307]. Lựa chọn: thêm 384 vào taxonomy, đổi CWE, hoặc chuyển vào `rules_disabled/` |
| pattern-regex không qua parser | 13 rule (`team.sql-injection`, `team.hardcoded-credentials`, `team.os-command-injection`, `team.path-traversal`, `team.sql-string-building`, `team.xss-html-string-building`, `team.hardcoded-auth-header`, `team.java.sqli-concat`, `team.java.xss-html-concat`, `team.js.sqli-string`, `team.js.xss-html-concat`, `team.php.sqli-string`, `team.php.xss-html-concat`) | Mục 5.2 chỉ cho regex khi parser không đọc được file. Viết lại bằng pattern AST phải đo lại trên train v2.2 (R2/R4); thêm `paths.include` không giải quyết bản chất |
| TC4 val không đạt | `team.js.audit.fs-path-api` (val 2/9) | Đo trên v5; theo mục 8.1 đo lại trên v2.2 trước khi tắt |
| TC5-audit: bản vá bị báo nhiều hơn bản lỗi | 14 rule audit | Mục 5.4: không đổi ngưỡng; TC5 so cả file nên yếu, hướng sửa (đo theo dòng bị sửa) chờ duyệt |
| Taint ở tầng audit | `team.path-from-parameter`, `team.php.path-taint` | Source của `path-from-parameter` là mọi tham số hàm (không phải request) nên không đủ chắc cho high; ghi ngoại lệ |
| Rule tắt dựa trên val + 4 ứng dụng | `team.java.auth-secret-equals`, `team.js.auth-secret-equality` (rules_disabled) | Train chỉ 1 và 3 lần báo (< 5): theo 5.4 “chưa đủ dữ liệu, không kết luận và không tắt”. Cần giải trình lại bằng train v2.2 hoặc bật lại |
| `team.php.xss-taint` báo 65 bản vá / 98 bản lỗi | 1 rule | Rà tay ~10 ca bản vá thuộc train v2.2 (nghi thiếu sanitizer) |
| Ô PHP PATH_TRAVERSAL (train 6/120, val 0/24 trên v5) | — | Viết rule hẹp từ FN của train v2.2 (≥ 3 mẫu cùng dạng) |
| `team.js.auth-weak-password-hash` khớp mọi `md5(...)` | 1 rule | TC3: nên giới hạn theo tên biến mật khẩu như bản Java (v4); cần đo trên train |
| Tên rule audit không có `.audit.` | 12 rule cũ (vd. `team.java.cmd-string`) | Mục 6: quy ước áp cho rule mới; đổi id cũ làm vỡ so sánh giữa các phiên bản nên giữ nguyên |

## 4. Chi tiết từng rule (trạng thái trước khi sửa, kèm xử lý)

| Rule | Ngôn ngữ | Lớp | Tầng | Kiểu | Test | TC4 (train/val v5) | TC5 (train) | Kết luận |
|---|---|---|---|---|---|---|---|---|
| `team.java.auth-jwt-unverified` | java | AUTHENTICATION_WEAKNESS | high | pattern | 1+/1- | train: 0 lần báo; val: 0 lần báo | 1/0 (<5) | **Còn tồn tại** — Còn: đổi tên lớp Auth |
| `team.java.auth-weak-password-hash` | java | AUTHENTICATION_WEAKNESS | audit | pattern | 1+/1- | train: 0/3 (<5, chưa đủ dữ liệu); val: 0 lần báo | 0/3 (<5) | **Còn tồn tại** — Còn: đổi tên lớp Auth, CWE-916 chờ xác nhận |
| `team.java.hardcoded-password-compare` | java | HARDCODED_CREDENTIALS | high | pattern | 1+/2- | train: 2/2 (<5, chưa đủ dữ liệu); val: 0 lần báo | 2/0 (<5) | **Đạt** |
| `team.java.hardcoded-secret` | java | HARDCODED_CREDENTIALS | high | pattern | 2+/2- | train: 4/4 (<5, chưa đủ dữ liệu); val: 0 lần báo | 4/0 (<5) | **Đạt** |
| `team.java.cmdi-taint` | java | OS_COMMAND_INJECTION | high | taint | 1+/3- | train: 0 lần báo; val: 0 lần báo | — | **Đạt** |
| `team.java.audit.process-api` | java | OS_COMMAND_INJECTION | audit | pattern | 1+/1- | train: 0 lần báo; val: 0 lần báo | — | **Đã sửa** — Đã sửa: severity |
| `team.java.cmd-string` | java | OS_COMMAND_INJECTION | audit | pattern | 1+/1- | train: 0 lần báo; val: 0 lần báo | — | **Đạt** |
| `team.java.audit.commandline-api` | java | OS_COMMAND_INJECTION | audit | pattern | 2+/2- | train: 6/6=1.00 đạt; val: 0 lần báo | lỗi 6 / vá 6: đạt | **Đã sửa** — Đã sửa: severity |
| `team.java.path-taint` | java | PATH_TRAVERSAL | high | taint | 1+/2- | train: 0 lần báo; val: 1/1 (<5, chưa đủ dữ liệu) | 0/1 (<5) | **Đạt** |
| `team.java.audit.file-path-api` | java | PATH_TRAVERSAL | audit | pattern | 3+/1- | train: 39/47=0.83 đạt; val: 18/21=0.86 đạt | lỗi 39 / vá 47: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.java.path-upload-name` | java | PATH_TRAVERSAL | audit | pattern | 1+/1- | train: 1/1 (<5, chưa đủ dữ liệu); val: 0 lần báo | 1/2 (<5) | **Đạt** |
| `team.java.sqli-taint` | java | SQL_INJECTION | high | taint | 2+/3- | train: 1/1 (<5, chưa đủ dữ liệu); val: 0 lần báo | 1/0 (<5) | **Đạt** |
| `team.java.audit.sql-api` | java | SQL_INJECTION | audit | pattern | 2+/1- | train: 40/40=1.00 đạt; val: 19/19=1.00 đạt | lỗi 40 / vá 21: đạt | **Đã sửa** — Đã sửa: severity |
| `team.java.sqli-concat` | java | SQL_INJECTION | audit | regex | 2+/1- | train: 33/33=1.00 đạt; val: 18/18=1.00 đạt | lỗi 33 / vá 11: đạt | **Còn tồn tại** — Còn: regex → viết lại AST |
| `team.java.xss-taint` | java | XSS | high | taint | 1+/1- | train: 0 lần báo; val: 0/1 (<5, chưa đủ dữ liệu) | — | **Đạt** |
| `team.java.audit.response-output` | java | XSS | audit | pattern | 2+/1- | train: 0 lần báo; val: 0/1 (<5, chưa đủ dữ liệu) | — | **Đã sửa** — Đã sửa: severity |
| `team.java.xss-html-concat` | java | XSS | audit | regex | 1+/1- | train: 4/6=0.67 đạt; val: 0 lần báo | 4/6 (<5) | **Còn tồn tại** — Còn: regex → viết lại AST |
| `team.java.xss-writer-output` | java | XSS | audit | pattern | 3+/3- | train: 0 lần báo; val: 0 lần báo | — | **Đạt** |
| `team.js.auth-jwt-unverified` | javascript | AUTHENTICATION_WEAKNESS | high | pattern | 1+/1- | train: 0 lần báo; val: 0 lần báo | — | **Còn tồn tại** — Còn: đổi tên lớp Auth |
| `team.js.auth-jwt-decode` | javascript | AUTHENTICATION_WEAKNESS | audit | pattern | 1+/1- | train: 0 lần báo; val: 0 lần báo | — | **Còn tồn tại** — Còn: đổi tên lớp Auth |
| `team.js.auth-weak-password-hash` | javascript | AUTHENTICATION_WEAKNESS | audit | pattern | 1+/1- | train: 0/1 (<5, chưa đủ dữ liệu); val: 0 lần báo | 0/2 (<5) | **Còn tồn tại** — Còn: đổi tên lớp Auth, CWE-916 chờ xác nhận |
| `team.js.hardcoded-password-compare` | javascript | HARDCODED_CREDENTIALS | high | pattern | 1+/3- | train: 2/2 (<5, chưa đủ dữ liệu); val: 0 lần báo | 2/0 (<5) | **Đạt** |
| `team.js.hardcoded-secret` | javascript | HARDCODED_CREDENTIALS | high | pattern | 3+/2- | train: 4/4 (<5, chưa đủ dữ liệu); val: 0 lần báo | 4/0 (<5) | **Đạt** |
| `team.js.cmdi-taint` | javascript | OS_COMMAND_INJECTION | high | taint | 1+/2- | train: 3/3 (<5, chưa đủ dữ liệu); val: 0 lần báo | 3/0 (<5) | **Đạt** |
| `team.js.cmd-shell` | javascript | OS_COMMAND_INJECTION | audit | pattern | 1+/2- | train: 11/11=1.00 đạt; val: 5/5=1.00 đạt | lỗi 11 / vá 6: đạt | **Đạt** |
| `team.js.audit.process-api` | javascript | OS_COMMAND_INJECTION | audit | pattern | 2+/2- | train: 44/45=0.98 đạt; val: 10/10=1.00 đạt | lỗi 44 / vá 34: đạt | **Đã sửa** — Đã sửa: severity |
| `team.js.path-taint` | javascript | PATH_TRAVERSAL | high | taint | 2+/2- | train: 0 lần báo; val: 0 lần báo | — | **Đạt** |
| `team.js.audit.fs-path-api` | javascript | PATH_TRAVERSAL | audit | pattern | 3+/4- | train: 29/43=0.67 đạt; val: 2/9=0.22 KHÔNG ĐẠT | lỗi 30 / vá 37: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC4 (đo lại v2.2), TC5-audit (đo lại theo dòng sửa) |
| `team.js.sqli-taint` | javascript | SQL_INJECTION | high | taint | 1+/2- | train: 0 lần báo; val: 0 lần báo | — | **Đạt** |
| `team.js.sqli-string` | javascript | SQL_INJECTION | audit | regex | 2+/1- | train: 3/3 (<5, chưa đủ dữ liệu); val: 0 lần báo | 3/3 (<5) | **Còn tồn tại** — Còn: regex → viết lại AST |
| `team.js.sqli-dynamic-query` | javascript | SQL_INJECTION | audit | pattern | 3+/2- | train: 0 lần báo; val: 0 lần báo | — | **Đạt** |
| `team.js.audit.sql-api` | javascript | SQL_INJECTION | audit | pattern | 1+/2- | train: 7/8=0.88 đạt; val: 0 lần báo | lỗi 7 / vá 8: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.js.xss-taint` | javascript | XSS | high | taint | 1+/2- | train: 0 lần báo; val: 3/3 (<5, chưa đủ dữ liệu) | 0/2 (<5) | **Đạt** |
| `team.js.xss-dom-sink` | javascript | XSS | audit | pattern | 1+/2- | train: 102/114=0.89 đạt; val: 28/29=0.97 đạt | lỗi 102 / vá 93: đạt | **Đạt** |
| `team.js.xss-html-concat` | javascript | XSS | audit | regex | 1+/1- | train: 94/101=0.93 đạt; val: 9/11=0.82 đạt | lỗi 94 / vá 86: đạt | **Còn tồn tại** — Còn: regex → viết lại AST |
| `team.js.xss-jquery-insert` | javascript | XSS | audit | pattern | 2+/3- | train: 60/61=0.98 đạt; val: 5/10=0.50 đạt | lỗi 60 / vá 58: đạt | **Đạt** |
| `team.php.auth-weak-password-hash` | php | AUTHENTICATION_WEAKNESS | audit | pattern | 1+/2- | train: 1/1 (<5, chưa đủ dữ liệu); val: 0 lần báo | 2/2 (<5) | **Còn tồn tại** — Còn: đổi tên lớp Auth, CWE-916 chờ xác nhận |
| `team.php.audit.auth-code` | php | AUTHENTICATION_WEAKNESS | audit | pattern | 2+/2- | train: 10/18=0.56 đạt; val: 1/1 (<5, chưa đủ dữ liệu) | lỗi 15 / vá 20: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: đổi tên lớp Auth, TC5-audit (đo lại theo dòng sửa) |
| `team.php.hardcoded-password-compare` | php | HARDCODED_CREDENTIALS | high | pattern | 1+/2- | train: 2/2 (<5, chưa đủ dữ liệu); val: 0/1 (<5, chưa đủ dữ liệu) | 2/0 (<5) | **Đạt** |
| `team.php.hardcoded-secret` | php | HARDCODED_CREDENTIALS | high | pattern | 4+/1- | train: 4/5=0.80 đạt; val: 1/1 (<5, chưa đủ dữ liệu) | 4/2 (<5) | **Đạt** |
| `team.php.cmdi-taint` | php | OS_COMMAND_INJECTION | high | taint | 1+/2- | train: 2/3 (<5, chưa đủ dữ liệu); val: 0 lần báo | 2/1 (<5) | **Đạt** |
| `team.php.cmd-dynamic` | php | OS_COMMAND_INJECTION | audit | pattern | 1+/2- | train: 7/8=0.88 đạt; val: 2/3 (<5, chưa đủ dữ liệu) | lỗi 7 / vá 9: KHÔNG ĐẠT | **Còn tồn tại** — Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.php.audit.process-api` | php | OS_COMMAND_INJECTION | audit | pattern | 2+/1- | train: 19/27=0.70 đạt; val: 2/3 (<5, chưa đủ dữ liệu) | lỗi 19 / vá 25: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.php.path-taint` | php | PATH_TRAVERSAL | high → audit | taint | 1+/1- | train: 7/13=0.54 KHÔNG ĐẠT; val: 0 lần báo | a/b 1.43: rà tay | **Đã sửa** — Đã sửa: hạ audit |
| `team.php.sqli-taint` | php | SQL_INJECTION | high | taint | 1+/2- | train: 34/37=0.92 đạt; val: 1/1 (<5, chưa đủ dữ liệu) | a/b 0.88: đạt | **Đạt** |
| `team.php.sqli-string` | php | SQL_INJECTION | audit | regex | 2+/1- | train: 73/87=0.84 đạt; val: 20/21=0.95 đạt | lỗi 71 / vá 82: KHÔNG ĐẠT | **Còn tồn tại** — Còn: regex → viết lại AST, TC5-audit (đo lại theo dòng sửa) |
| `team.php.audit.sql-api` | php | SQL_INJECTION | audit | pattern | 3+/3- | train: 151/172=0.88 đạt; val: 25/30=0.83 đạt | lỗi 149 / vá 159: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.php.xss-taint` | php | XSS | high | taint | 1+/2- | train: 98/105=0.93 đạt; val: 5/5=1.00 đạt | a/b 0.65: đạt | **Đạt** |
| `team.php.xss-html-concat` | php | XSS | audit | regex | 1+/1- | train: 131/152=0.86 đạt; val: 11/16=0.69 đạt | lỗi 132 / vá 131: đạt | **Còn tồn tại** — Còn: regex → viết lại AST |
| `team.php.audit.echo-unescaped` | php | XSS | audit | pattern | 2+/3- | train: 275/312=0.88 đạt; val: 23/27=0.85 đạt | lỗi 276 / vá 294: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.php.xss-template-request` | php | XSS | high | regex | 3+/2- | train: 43/44=0.98 đạt; val: 3/3 (<5, chưa đủ dữ liệu) | a/b 0.05: đạt | **Đạt** |
| `team.php.audit.xss-template-echo` | php | XSS | audit | regex | 2+/3- | train: 114/120=0.95 đạt; val: 6/7=0.86 đạt | lỗi 115 / vá 96: đạt | **Đã sửa** — Đã sửa: severity |
| `team.authentication-weakness` | python | AUTHENTICATION_WEAKNESS | high | pattern | 1+/1- | train: 0 lần báo; val: 0 lần báo | — | **Còn tồn tại** — Đã sửa: severity; Còn: đổi tên lớp Auth |
| `team.audit.auth-code` | python | AUTHENTICATION_WEAKNESS | audit | pattern | 2+/2- | train: 7/9=0.78 đạt; val: 4/5=0.80 đạt | lỗi 8 / vá 10: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: đổi tên lớp Auth, TC5-audit (đo lại theo dòng sửa) |
| `team.auth-secret-equality` | python | AUTHENTICATION_WEAKNESS | audit | pattern | 1+/3- | train: 1/1 (<5, chưa đủ dữ liệu); val: 1/1 (<5, chưa đủ dữ liệu) | 1/1 (<5) | **Còn tồn tại** — Còn: đổi tên lớp Auth |
| `team.auth-session-fixation` | python | AUTHENTICATION_WEAKNESS | audit | pattern | 1+/1- | train: 0 lần báo; val: 0 lần báo | — | **Còn tồn tại** — Còn: đổi tên lớp Auth, CWE-384 ngoài taxonomy |
| `team.auth-weak-password-hash` | python | AUTHENTICATION_WEAKNESS | audit | pattern | 1+/1- | train: 0 lần báo; val: 0 lần báo | — | **Còn tồn tại** — Còn: đổi tên lớp Auth, CWE-916 chờ xác nhận |
| `team.hardcoded-auth-header` | python | HARDCODED_CREDENTIALS | high | regex | 2+/2- | train: 4/4 (<5, chưa đủ dữ liệu); val: 0 lần báo | 4/0 (<5) | **Còn tồn tại** — Đã sửa: severity; Còn: regex → viết lại AST |
| `team.hardcoded-credentials` | python | HARDCODED_CREDENTIALS | high | regex | 2+/1- | train: 0/2 (<5, chưa đủ dữ liệu); val: 2/2 (<5, chưa đủ dữ liệu) | 0/2 (<5) | **Còn tồn tại** — Đã sửa: severity; Còn: regex → viết lại AST |
| `team.py.hardcoded-password-compare` | python | HARDCODED_CREDENTIALS | high | pattern | 1+/2- | train: 2/2 (<5, chưa đủ dữ liệu); val: 0 lần báo | 2/0 (<5) | **Đạt** |
| `team.os-command-injection` | python | OS_COMMAND_INJECTION | high | regex | 4+/3- | train: 15/15=1.00 đạt; val: 4/4 (<5, chưa đủ dữ liệu) | a/b 0.20: đạt | **Còn tồn tại** — Đã sửa: severity; Còn: regex → viết lại AST |
| `team.os-command-string-building` | python | OS_COMMAND_INJECTION | high | pattern | 1+/1- | train: 1/1 (<5, chưa đủ dữ liệu); val: 0 lần báo | 1/0 (<5) | **Đã sửa** — Đã sửa: severity |
| `team.py.cmdi-taint` | python | OS_COMMAND_INJECTION | high | taint | 1+/3- | train: 0 lần báo; val: 0 lần báo | — | **Đạt** |
| `team.audit.process-api` | python | OS_COMMAND_INJECTION | audit | pattern | 3+/1- | train: 11/11=1.00 đạt; val: 4/4 (<5, chưa đủ dữ liệu) | lỗi 11 / vá 16: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.path-request-taint` | python | PATH_TRAVERSAL | high | taint | 2+/2- | train: 6/6=1.00 đạt; val: 0 lần báo | a/b 0.50: đạt | **Đạt** |
| `team.path-traversal` | python | PATH_TRAVERSAL | high | regex | 1+/1- | train: 0 lần báo; val: 0/1 (<5, chưa đủ dữ liệu) | — | **Còn tồn tại** — Đã sửa: severity; Còn: regex → viết lại AST |
| `team.archive-extract-all` | python | PATH_TRAVERSAL | audit | pattern | 1+/1- | train: 9/9=1.00 đạt; val: 0 lần báo | lỗi 9 / vá 9: đạt | **Đạt** |
| `team.audit.file-path-api` | python | PATH_TRAVERSAL | audit | pattern | 1+/1- | train: 43/52=0.83 đạt; val: 3/6=0.50 đạt | lỗi 54 / vá 68: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.path-from-parameter` | python | PATH_TRAVERSAL | audit | taint | 1+/3- | train: 30/34=0.88 đạt; val: 4/4 (<5, chưa đủ dữ liệu) | lỗi 38 / vá 24: đạt | **Còn tồn tại** — Còn: taint ở audit (ngoại lệ) |
| `team.py.audit.pathlib-api` | python | PATH_TRAVERSAL | audit | pattern | 2+/2- | train: 27/30=0.90 đạt; val: 5/7=0.71 đạt | lỗi 27 / vá 28: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.py.sqli-taint` | python | SQL_INJECTION | high | taint | 1+/2- | train: 3/3 (<5, chưa đủ dữ liệu); val: 0 lần báo | 3/0 (<5) | **Đạt** |
| `team.sql-injection` | python | SQL_INJECTION | high | regex | 1+/2- | train: 6/7=0.86 đạt; val: 0 lần báo | a/b 0.67: đạt | **Còn tồn tại** — Đã sửa: severity; Còn: regex → viết lại AST |
| `team.audit.sql-api` | python | SQL_INJECTION | audit | pattern | 1+/2- | train: 13/14=0.93 đạt; val: 0 lần báo | lỗi 13 / vá 7: đạt | **Đã sửa** — Đã sửa: severity |
| `team.sql-string-building` | python | SQL_INJECTION | audit | regex | 3+/2- | train: 9/10=0.90 đạt; val: 2/2 (<5, chưa đủ dữ liệu) | lỗi 9 / vá 2: đạt | **Còn tồn tại** — Còn: regex → viết lại AST |
| `team.py.xss-taint` | python | XSS | high | taint | 1+/2- | train: 1/3 (<5, chưa đủ dữ liệu); val: 0/1 (<5, chưa đủ dữ liệu) | 1/3 (<5) | **Đạt** |
| `team.xss-response-formatting` | python | XSS | high | pattern | 2+/1- | train: 1/1 (<5, chưa đủ dữ liệu); val: 0 lần báo | 1/1 (<5) | **Đã sửa** — Đã sửa: severity |
| `team.xss-unsafe-html` | python | XSS | high | pattern | 2+/2- | train: 10/11=0.91 đạt; val: 1/1 (<5, chưa đủ dữ liệu) | a/b 1.00: đạt | **Đã sửa** — Đã sửa: severity |
| `team.audit.html-output-api` | python | XSS | audit | pattern | 1+/2- | train: 17/25=0.68 đạt; val: 0/1 (<5, chưa đủ dữ liệu) | lỗi 17 / vá 29: KHÔNG ĐẠT | **Còn tồn tại** — Đã sửa: severity; Còn: TC5-audit (đo lại theo dòng sửa) |
| `team.xss-html-string-building` | python | XSS | audit | regex | 2+/1- | train: 13/14=0.93 đạt; val: 0 lần báo | lỗi 13 / vá 13: đạt | **Còn tồn tại** — Còn: regex → viết lại AST |
| `team.py.xss-jinja-autoescape-default` | python | XSS | audit | pattern | 1+/1- | train: 4/6=0.67 đạt; val: 1/1 (<5, chưa đủ dữ liệu) | 4/7 (<5) | **Đạt** |
| `team.py.audit.response-body` | python | XSS | audit | pattern | 1+/1- | train: 0 lần báo; val: 4/4 (<5, chưa đủ dữ liệu) | — | **Đã sửa** — Đã sửa: severity |

## 5. Điều chưa chắc chắn

- Mọi số TC4/TC5 đo trên train/val v5 và cặp a01, chưa đo trên v2.2; chưa kiểm tra chồng lấn giữa dữ liệu chỉnh v4.2 và test v2.2 (mục 8.4).
- Chưa chạy `ruleset.py all`/`verify` cho v4.3.0 trên Semgrep 1.181.0; các thay đổi chỉ đụng `severity`, `confidence` (1 rule) và metadata nên dự kiến 270/270 test vẫn đạt, nhưng phải xác nhận bằng lần chạy thật.
- Hạ `team.php.path-taint` đi ngược quyết định giữ high ngày 21/10; nếu nhóm giữ quyết định cũ thì khôi phục từ `archive/rules_v4.2.0/php/path_traversal.yml` và ghi lý do.
- Đánh giá “audit chỉ khớp giá trị động” cho 5 rule không có `pattern-not` là đọc tay nội dung pattern, không phải đo.
