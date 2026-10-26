# Tiêu chí chọn rule Semgrep cho AI-WhiteSec-CI (áp dụng từ ruleset v4.2.0)

Tài liệu này cụ thể hóa phương pháp 5 bước trong bài *Writing Semgrep rules: a methodology*
(semgrep.dev, 2020) cho phạm vi đồ án (6 lớp lỗ hổng × Python/Java/JavaScript/PHP, luồng SAST chạy song
song với CodeBERT) và ghi lại quyết định lọc/bổ sung rule của bản v4.2.0.

## 1. Phương pháp của Semgrep và cách áp dụng vào đồ án

| Bước trong bài | Áp dụng trong đồ án |
|---|---|
| 1. Chọn điều cần tìm (phân tích biến thể lỗ hổng đã biết, rà API nguy hiểm) | Lấy mẫu **bị bỏ sót trên train v5** theo từng ô ngôn ngữ × lớp (bảng K03), tìm sink chung |
| 2. Cụ thể hóa thành đoạn code đúng/sai | Mỗi ý tưởng phải có ví dụ code lỗi và code an toàn lấy từ dữ liệu thật hoặc bản vá (cặp a01) |
| 3. Viết test và rule ban đầu; `pattern` rồi thêm `pattern-not`, `pattern-either` | `tests/positive` (`ruleid:`) và `tests/negative` (`ok:`); `tools/ruleset.py check/test` |
| 4. Lặp: quét repo thật, gom báo nhầm theo nguyên nhân chung để lọc; rà báo sót bằng tìm kiếm văn bản | Đo trên train (chỉnh), val (đánh giá), cặp a01 (bản lỗi/bản vá) và 4 ứng dụng; **rà tay** từng báo nhầm |
| 5. Đưa vào CI: chặn build khi độ tin cậy cao, chỉ cảnh báo khi cần rà | Tầng `high` → có thể BLOCK; tầng `audit` → REVIEW. Khóa phiên bản bằng manifest + `ruleset.py verify` |

## 2. Tiêu chí

Một rule được **giữ** (hoặc **thêm**) khi đạt đủ TC1–TC7; được xếp tầng theo TC8.

| Mã | Tiêu chí | Cách kiểm |
|---|---|---|
| TC1 | **Đúng phạm vi:** rule thuộc 1 trong 6 lớp (CWE nằm trong `CWE_TO_CLASS`: 89, 79, 78/77/88, 22/23/36, 287/306/307, 798/259/321; CWE-916 xếp vào AUTH theo metadata) và 1 trong 4 ngôn ngữ. Rule ngoài phạm vi không viết thành custom rule; finding registry ngoài phạm vi chỉ mang tính thông tin, không gán lớp. | `ruleset.py check` (vuln_class khớp tên file) |
| TC2 | **Xuất phát từ mẫu thật, có độ phủ mới:** rule mới phải bắt được **≥ 3 mẫu train** mà bộ hiện tại đang bỏ sót. Chỉ chỉnh rule bằng train; val chỉ để đánh giá; **không bao giờ dùng test**. | `21_rule_metrics.py` cột "chỉ rule này bắt đúng" trên train |
| TC3 | **Mô tả điểm yếu, không chỉ định vị code:** rule phải trỏ tới sink nguy hiểm hoặc cấu hình sai. Rule **không được** khớp chính API an toàn được khuyến nghị (vd. `hmac.compare_digest`, `password_verify`). Rule kiểu "đây là code đăng nhập" chỉ được ở tầng audit và vẫn phải qua TC4. | Đọc rule + negative test có API an toàn |
| TC4 | **Ngưỡng số liệu** (tỉ lệ báo đúng lớp trên mẫu có lỗ hổng): `audit` ≥ 0,50 trên train và không dưới 0,50 trên val khi val có ≥ 5 lần báo; `high` ≥ 0,80 (≥ 5 lần báo). Rule không đạt → sửa hoặc tắt. | `21_rule_metrics.py` train/val |
| TC5 | **Phân biệt bản lỗi và bản đã vá** (dữ liệu cặp a01), **so với mức nền** của cả bộ rule: mức nền = tổng bản vá bị báo / tổng bản lỗi báo đúng lớp (v4.2 train: 1.594/1.719 = 0,93; gần 1 vì bản vá thường chỉ khác bản lỗi ~2 dòng, sink vẫn còn). Với rule có b_đúng ≥ 5: a/b_đúng ≤ 0,5 × mức nền → phân biệt tốt; ≥ 1,5 × mức nền → **rà tay theo TC6**. TC5 chỉ là tín hiệu, không tự nó hạ tầng hay tắt rule. Bản đầu dùng ngưỡng cố định ≤ 0,30, gắn cờ gần như mọi rule nên đã bỏ (v4.2, 21/10). Tiêu chí này bù cho điểm yếu của TC4: dữ liệu v5 chỉ có code có lỗ hổng. | `30_rule_pairs_diff.py` |
| TC6 | **Rà tay báo nhầm trước khi kết luận:** ground truth của 4 ứng dụng chỉ ghi lỗ hổng chính, nên "báo nhầm" có thể là lỗi thật ngoài GT (vd. `String PASSWORD = "!!webgoat_admin_1234!!"`, `md5($pass_new)` trong DVWA, `bypassSecurityTrustHtml` với dữ liệu người dùng trong Juice Shop). “Sai lớp” trên dữ liệu v5 cũng không đồng nghĩa báo nhầm: hàm có thể chứa thêm lỗi khác với nhãn của mẫu. Chỉ sửa rule khi xác định được **nguyên nhân chung** (≥ 2 báo nhầm cùng dạng), bằng `pattern-not`/`metavariable-regex`, và thêm negative test cho dạng đó. | Bảng rà tay (mục 4) |
| TC7 | **Chuẩn kỹ thuật:** đủ metadata (`cwe`, `owasp`, `vuln_class`, `confidence`, `severity`, `scope`, `rule_version`, `ruleset_version`, ghi chú thay đổi), có positive và negative test, toàn bộ test đạt, bundle + manifest khóa SHA-256 và phiên bản Semgrep 1.181.0. Rule `regex` chỉ dùng khi parser của Semgrep không đọc được loại file đó (template PHP), và phải giới hạn `paths.include`. | `ruleset.py all` → `regression_passed: true` |
| TC8 | **Xếp tầng:** `high` = luồng taint source → sink không qua sanitizer, hoặc mẫu gần như chắc chắn sai (tắt kiểm tra chữ ký JWT, mật khẩu viết cứng, in thẳng `$_GET` ra template); `audit` = dùng API nguy hiểm với giá trị không phải hằng, cần người rà. | Đọc rule + TC4/TC5 |

Rule **không báo lần nào** trên train/val (thường là rule taint: hàm rời không chứa source) vẫn được giữ nếu
đạt TC1, TC3, TC7 và không có báo nhầm đã xác nhận trên 4 ứng dụng, vì khi quét cả file trong repo thật source
và sink có thể nằm cùng nhau.

## 3. Thay đổi của v4.2.0 (84 → 81 rule đang dùng)

### Thêm (2 rule)

| Rule | Tầng | Bằng chứng |
|---|---|---|
| `team.php.xss-template-request` | high | Phần lớn PHP XSS bị bỏ sót là file template (HTML xen `<?= ?>`) mà parser PHP báo PARSE_ERROR/PARTIAL_PARSE; khi đó cả rule `pattern-regex` khai báo `languages: [php]` cũng không chạy (0 finding trên mẫu lỗi parse). Rule dùng `languages: [regex]` + `paths.include: *.php`. Train: 44 lần báo, 43 đúng lớp (0,98), 13 mẫu mới; cặp a01 train: bản lỗi 44, bản vá 2 (a/b = 0,05). Tầng high PHP XSS train 97 → 111. |
| `team.php.audit.xss-template-echo` | audit | Train: 120 lần báo, 114 đúng lớp (0,95), 23 mẫu mới; cặp a01: 122 / 96 → không phân biệt tốt bản vá nên chỉ ở audit. |

Ý tưởng **đã thử nhưng không thêm** (không đạt TC2): Java `StringBuilder.append("<p>").append(x)` chỉ khớp
1 mẫu train; Java/JS/Python AUTHENTICATION_WEAKNESS bị sót chủ yếu là logic phân quyền, SAML, hàm kiểm thử,
không có sink chung để viết mẫu, nên để CodeBERT xử lý.

### Sửa (4 rule, nâng `rule_version` lên 1.1.0, có negative test cho dạng báo nhầm)

| Rule | Nguyên nhân báo nhầm (TC6) | Sửa |
|---|---|---|
| `team.java.sqli-taint` (high) | `super.execute(file, fullName)` trong WebGoat ProfileUpload bị coi là JDBC (2 báo nhầm + 1 sai lớp) | `pattern-not: super.execute(...)` |
| `team.js.hardcoded-password-compare` (high) | `newPassword === 'undefined'` (Juice Shop changePassword/resetPassword) | Bỏ literal `undefined/null/true/false/none/nil/nan` |
| `team.js.audit.fs-path-api` (audit) | `res.sendFile(path.resolve('frontend/.../index.html'))` (đường dẫn toàn hằng) | `pattern-not` cho `path.*("...")`, `path.*(__dirname, "...")` |
| `team.audit.auth-code` (audit, Python) | Rule khớp `hmac.compare_digest`, `check_password`, `check_password_hash` — chính là API an toàn (vi phạm TC3) | Bỏ 3 API này khỏi rule |

Không sửa `team.java.xss-taint` (1 báo nhầm: `PrintWriter` ghi file log trong WebGoat `Ping.java`) vì chưa đủ
2 trường hợp cùng dạng (TC6); theo dõi tiếp.

### Tắt (5 rule, chuyển sang `rules_disabled/`, lý do ghi ở `metadata.disabled_v42`)

| Rule | Tiêu chí không đạt | Số liệu |
|---|---|---|
| `team.java.audit.auth-code` | TC3, TC4 | train 1/8 (0,12); val 0 lần báo; 4 ứng dụng 2/12 |
| `team.java.auth-secret-equals` | TC4 | train 0/1; val 0/2; WebGoat 1/10 |
| `team.php.auth-secret-equality` | TC4 | train 0/7; DVWA 9 báo nhầm `$pass_new == $pass_conf` (so với mật khẩu nhập lại) |
| `team.js.auth-secret-equality` | TC4 | train 0/3; val 0 lần báo; Juice Shop 1/9 (`password !== passwordRepeat`) |
| `team.php.audit.file-path-api` | TC4 | train 0,27 (18/66); val 0,38 (3/8); cặp val 3 đúng / 5 sai lớp |

**Đánh đổi cần biết:** tắt `team.php.audit.file-path-api` làm ô PHP PATH_TRAVERSAL của custom rule giảm từ
19/120 → 6/120 (train) và 3/24 → 0/24 (val). Nếu nhóm cần giữ ô này, hướng đúng là viết rule hẹp hơn (đường dẫn
lấy từ `$_GET/$_POST/$_FILES['name']` hoặc `include/require` với biến) rồi đo lại theo TC4, không bật lại rule cũ.

## 4. Kết quả ước lượng (trước khi chạy Semgrep thật, giữ để đối chiếu)

Ước lượng bằng cách bỏ finding của rule đã tắt/đã sửa khỏi kết quả v4.1 có sẵn và chạy regex của 2 rule mới bằng
Python (phương pháp tái lập đúng số liệu v4.1 đã báo cáo). Chỉ custom rule cho train/val; SAST_B (custom +
registry) cho 4 ứng dụng.

| Tập | Chỉ số | v4.1 | v4.2 (ước lượng) |
|---|---|---:|---:|
| train v5 (3.497 mẫu) | Recall (≥ 1 finding đúng lớp) | 0,322 | 0,328 |
| | Recall tầng high | 0,059 | 0,063 |
| | Tỉ lệ finding đúng lớp | 0,846 | 0,883 |
| val v5 (693 mẫu) | Recall | 0,270 | 0,268 |
| | Recall tầng high | 0,026 | 0,029 |
| | Tỉ lệ finding đúng lớp | 0,821 | 0,841 |
| 4 ứng dụng (SAST_B) | Lỗ hổng phát hiện đúng lớp | 60/78 | 58/78 |
| | Đơn vị an toàn bị báo | 97/503 | 76/503 |
| | Precision | 0,27 | 0,32 |

Hai lỗ hổng mất trên ứng dụng là do tắt `team.java.audit.auth-code`/`team.java.auth-secret-equals` (WebGoat)
và `team.js.auth-secret-equality` (Juice Shop).

**Lưu ý về tính khách quan:** quyết định sửa/tắt có dùng kết quả rà tay trên 4 ứng dụng (đúng bước 4 của
phương pháp), nên số liệu 4 ứng dụng của v4.2 là **lạc quan**. Khi báo cáo, dùng tập **test** (chưa dùng để chọn
rule) làm số liệu cuối cùng và ghi rõ điều này.

## 5. Cách chạy để có số liệu thật

Từ thư mục `main/`, nhấp đúp `run_v42.bat` (dùng `.venv` và Semgrep 1.181.0 đã ghim). File chạy lần lượt:
`ruleset.py all` + `verify` (dừng nếu test rule không đạt), unit test, `21_rule_metrics.py` trên val/train
(so v3/v4.0/v4.1/v4.2), `30_rule_pairs_diff.py` (TC5) trên cặp train/val, đánh giá Gate trên cặp val
(**không** ghi đè `models/gate_config.json`), quét lại 4 ứng dụng với hậu tố `_v42`. Nhật ký:
`reports/v42_run_log.txt`.

Quay lại v4.1: bản đầy đủ ở `experiments/semgrep_v41_backup/`; bundle và manifest ở
`archive/semgrep_v4.1.0.yml`, `archive/ruleset-manifest_v4.1.0.json`
(`03_run_sast.py --rules security-config/semgrep/archive/semgrep_v4.1.0.yml`).

## 6. Kết quả thật v4.2.0 (run_v42.bat, 21/10/2026)

Kiểm tra: `ruleset.py check` 81 rule, 0 vấn đề; test 270/270; `regression_passed=True`; unit test 51/51.

| Tập | Chỉ số | v4.1 | v4.2 |
|---|---|---:|---:|
| val v5 | Recall / tỉ lệ đúng lớp | 0,270 / 0,821 | 0,268 / 0,841 |
| train v5 | Recall / recall tầng high / tỉ lệ đúng lớp | 0,322 / 0,060 / 0,846 | 0,328 / 0,064 / 0,884 |
| 4 ứng dụng | SAST_B: đúng lớp / hàm an toàn bị báo / precision | 60/78 · 97/503 · 0,27 | 58/78 · 74/503 · 0,32 |
| 4 ứng dụng | Tầng high: precision / hàm an toàn bị báo | 0,51 · 23 | 0,56 · 20 |
| 4 ứng dụng | Gate BLOCK: đúng lớp / hàm an toàn bị báo / precision | 34 · 37 · 0,34 | 34 · 32 · 0,40 |
| cặp val, ngưỡng 0,594 | Gate BLOCK: bản lỗi / bản vá | 19,8% / 6,9% | 20,1% / 6,9% |

Nguồn: `reports/rule_metrics_v42_{val,train}.md`, `reports/targets_v42.md`, `reports/gate_eval_val_v42.json` (khóa `sweep`).
`gate_eval_val_v42.md` chọn lại ngưỡng 0,638 (J 0,3702 so với 0,3697 ở 0,594); **nhóm giữ 0,594** trong
`models/gate_config.json` để kết quả 4 ứng dụng không phải chạy lại. Bảng `.md` đó ghi nhãn "SAST v4.1" do tên viết cứng
trong `25_gate_eval.py`; dữ liệu là v4.2.

TC5 theo mức nền (cặp train): phân biệt tốt `team.php.xss-template-request` (0,05), `team.os-command-injection` (0,20),
`team.sql-string-building` (0,22), `team.java.sqli-concat` (0,33); cần rà tay `team.php.path-taint` (1,43),
`team.audit.process-api` (1,45), `team.audit.html-output-api` (1,71).

### Rà tay `team.php.path-taint` (tầng high) — giữ nguyên

K03 gắn cờ rule này (train 7/13 đúng lớp, dưới 0,80) và TC5 xếp "kém hơn mức nền". Rà từng finding cho thấy đó là giới hạn
của nhãn, không phải báo nhầm:

- 3 finding trên DVWA (`view_help.php`, `view_source_all.php`, `view_source.php`) đều đọc file từ `$_GET['id']` không kiểm tra,
  ví dụ `eval(file_get_contents(".../{$id}/help/help.php"))`; `switch ($id)` trong `view_source.php` có nhánh `default` không
  dừng. Đây là path traversal thật (giới hạn đuôi file), ground truth DVWA chỉ ghi các bài lab chính.
- 6 finding "sai lớp" trên train nằm trong hàm mang nhãn SQLi/XSS nhưng có lỗi đường dẫn thật, ví dụ
  `include(dirname(__FILE__) . "/src/bat/" . $_GET["bat"] . ".php")` (nhãn XSS),
  `file_get_contents(... . esc_html($_POST["css_file_selection"]))` (`esc_html` không chặn `../`); 4 trường hợp còn lại cần ngữ cảnh.
- Bản vá vẫn bị báo vì bản vá trong a01 thường để nguyên sink.

Kết luận: chưa có báo nhầm nào được xác nhận, rule giữ tầng high. Ghi chú: finding high mà chỉ SAST báo sẽ bị Gate BLOCK
(`compare_gate.py`), nên mọi lần hạ tầng/tắt rule high phải qua rà tay như trên.

## 7. Bổ sung theo `docs/semgrep_tool.md` v1.2 (2026-10-25, ruleset v4.3.0)

- Tên lớp và danh sách CWE lấy từ `docs/taxonomy.yml` (v0.3.0). `tools/ruleset.py check` đối chiếu từng rule với file này.
- Quy tắc ba trường mức độ (mục 5.3): `severity` của Semgrep **chỉ suy từ `confidence`** (high → ERROR, audit → WARNING); `metadata.severity` **chỉ suy từ lớp**. Lệch là lỗi chặn phát hành.
- Rule có **< 5 lần báo** trên train: ghi “chưa đủ dữ liệu”, không kết luận và không tắt. Rule `high` không đạt TC4 thì **hạ xuống `audit`** trước; chỉ tắt khi rớt cả ngưỡng `audit`.
- Không dùng Bandit (kể cả làm đối chứng); manifest không còn ghi phiên bản Bandit.
- Số liệu chính thức đo trên dataset **v2.2**; số trong mục 3–6 (train/val v5, cặp a01) phải đo lại trước khi dựa vào.
- Kết quả kiểm tra 81 rule theo các tiêu chí trên: `reports/r2_kiem_tra_tieu_chi_v42_2026-10-25.md`.

## 8. Ruleset v4.3.1 (2026-10-25): ghi lý do ngoại lệ tầng

- Hai rule taint ở tầng `audit` (ngoại lệ của mục 5.2 “taint → high”) nay có `metadata.tier_exception` ghi lý do: `team.path-from-parameter` (Python, `rule_version` 1.1.0) và `team.php.path-taint` (PHP, 1.2.0).
- `tools/ruleset.py check`: rule taint ở `audit` **có** `tier_exception` (≥ 30 ký tự) không còn bị cảnh báo mà được liệt kê ở mục “Ngoại lệ tầng” của `reports/rule_test_report.md` và ở `tier_exceptions` trong manifest. Rule taint ở `audit` không ghi lý do vẫn bị cảnh báo.
- Không đổi pattern, không đổi kết quả quét: chỉ đổi metadata, nên bundle có SHA-256 mới. Bản v4.3.0 lưu ở `archive/`.
- Số cảnh báo của `check`: 32 → 30.

## 9. Ruleset v4.4.0 (2026-10-25): R2 theo đo nền train/val v2.2

- `team.php.sqli-taint` hạ high → audit (TC4: 7/11 = 0,64 trên train v2.2), ghi `tier_exception`.
- `team.php.xss-taint` thêm sanitizer (`strip_tags`, `absint`, `esc_*`, …) sau khi rà tay các mẫu báo sai trên train; chờ đo lại, nếu train < 0,80 thì hạ audit.
- 4 rule audit rớt TC4 (`team.php.xss-html-concat`, `team.audit.file-path-api`, `team.php.audit.auth-code`, `team.audit.auth-code`): chưa sửa pattern, lý do và đề xuất trong `reports/r2_thay_doi_v44_2026-10-25.md`.
- Số liệu v4.3.1 lưu ở `reports/r1_v431/` (do `run_r2_v44.bat` sao lưu trước khi đo lại).
