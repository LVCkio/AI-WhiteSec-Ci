# Task 1 và 2 — Rà nhãn nghi ngờ và xử lý rule audit yếu

Ngày 26/10/2026. Dataset v2.2; Semgrep 1.181.0; taxonomy 0.3.0; ruleset **v4.6.0**. Đầu vào v4.5.0: 83 rule. Đầu ra: **79 rule đang bật**, 287/287 kiểm thử đạt và `ruleset.py verify` đạt.

## Task 1: đã rà kỹ thuật đủ 11 ca

Phạm vi gồm chín mẫu âm mà rule query_single mới báo và hai mẫu dương có ý kiến AI trước đó là UNSURE. Đã đọc đoạn code, bản trước/sau sửa khi có, và mã upstream ở đúng commit để kiểm tra helper và nguồn dữ liệu. Việc này là rà kỹ thuật bằng AI, chưa thay thế xác nhận nhãn bởi con người.

| Kết luận tại phạm vi finding SQL | Số ca | Xử lý |
|---|---:|---|
| Chưa xác nhận SQLi tại vị trí được báo | 4 | Giữ bản dữ liệu gốc; lưu phân tích có điều kiện, không chứng nhận cả sáu nhóm đều sạch |
| HOLD mẫu âm | 4 | Chưa đủ ngữ cảnh để công nhận nhãn âm hoặc đổi thành dương |
| HOLD mẫu dương | 2 | Giữ UNSURE; không coi diff hoặc tên helper là bằng chứng nhãn chắc chắn |
| Xung đột với cách thu thập mẫu âm | 1 | Đề xuất cách ly khi xây bản dữ liệu đã được duyệt |

**Không có nhãn gốc nào bị sửa.** Các cột quyết định/người/ngày duyệt được để trống trong `BANG_DUYET_11_MAU.csv`; không điền ý kiến AI vào cột người duyệt. `candidate_exclusions.json` ghi bảy ID không nên dùng làm bằng chứng nhãn đã chắc chắn trong bản dữ liệu kế tiếp; đề xuất này chưa được áp dụng vào train/val hoặc số đo ở dưới.

### Phát hiện quan trọng

Mẫu `cvefixes-unch-31091058894844-159-423`, hàm `nvweb_template_parse`, mang nhãn âm do bộ tạo mẫu chọn hàm “không bị sửa”. Tuy nhiên, cùng truy vấn dùng `protect($current['lang'])` trong hàm đó được [bản vá upstream](https://github.com/NavigateCMS/Navigate-CMS/commit/6df73ccca64253a5e81c23356943fae50ffc836f) chuyển sang `:lang` và bindings. Điều này làm suy yếu căn cứ thu thập nhãn âm của chính mẫu đó. Đây là xung đột provenance cần cách ly/rà lại; chưa tự động chứng minh mẫu phải mang nhãn SQL_INJECTION.

Đã tìm được chuỗi gọi thật: `protect()` trong core gọi `database::protect()`, rồi `mb_escape()`. Helper có xử lý escape và quote, vì vậy không được coi nó như hàm không làm gì; cũng không được mặc nhiên coi nó an toàn trong mọi SQL mode, kiểu dữ liệu và caller. Không có PHP/MySQL lịch sử đang chạy để xác nhận tính khai thác của từng ca trong vòng này.

Nguồn được ghim:

- Parent trước sửa: `a56ff90a5dde53a7e90c49081eb35c9b098e961f`.
- Commit sửa: `6df73ccca64253a5e81c23356943fae50ffc836f`.
- [core protect, parent](https://github.com/NavigateCMS/Navigate-CMS/blob/a56ff90a5dde53a7e90c49081eb35c9b098e961f/lib/core/core.php#L51).
- [database protect, parent](https://github.com/NavigateCMS/Navigate-CMS/blob/a56ff90a5dde53a7e90c49081eb35c9b098e961f/lib/core/database.class.php#L396).
- [mb_escape, parent](https://github.com/NavigateCMS/Navigate-CMS/blob/a56ff90a5dde53a7e90c49081eb35c9b098e961f/lib/core/misc.php#L898).
- [query_single, bản sửa](https://github.com/NavigateCMS/Navigate-CMS/blob/6df73ccca64253a5e81c23356943fae50ffc836f/lib/core/database.class.php#L159).
- [nvweb_template_parse, bản sửa](https://github.com/NavigateCMS/Navigate-CMS/blob/6df73ccca64253a5e81c23356943fae50ffc836f/web/nvweb_templates.php#L322).

Lưu ý về phiên bản: metadata CVEfixes ghi commit sửa, nhưng mẫu `before_fix` và `unchanged` xuất phát từ code_before. Đã dùng parent để đọc ngữ cảnh các mẫu này, thay vì lấy mã sau sửa làm bằng chứng cho mẫu trước sửa. Chỉ có placeholder không đủ để chứng nhận câu SQL an toàn nếu phần khác vẫn ghép dữ liệu không được kiểm soát; [tài liệu PDO](https://www.php.net/manual/en/pdo.prepared-statements.php) cũng nêu giới hạn này.

## Task 2: chuyển bốn rule audit không đạt sang danh sách tắt

Quyết định dựa vào train và nội dung rule theo tiêu chí TC3/TC4 sẵn có. Không sửa pattern để chạy theo kết quả validation; không gán Semgrep làm nhãn dataset.

| Rule | Đúng lớp / lần báo trên mẫu dương train | Mẫu âm train bị báo | Lý do xử lý |
|---|---:|---:|---|
| `team.php.xss-html-concat` | 39/93 = 41,9% | 156 | Regex chỉ nhận diện dựng chuỗi HTML, chưa chứng minh đi vào sink không an toàn; có thể khớp mã escape hoặc xử lý số |
| `team.audit.file-path-api` | 9/28 = 32,1% | 36 | open/copy/remove với đường dẫn động không tự chứng minh traversal hoặc quyền kiểm soát bên ngoài |
| `team.php.audit.auth-code` | 3/9 = 33,3% | 13 | Tên hàm login, isGranted và ghi session chỉ cho thấy có chức năng xác thực |
| `team.audit.auth-code` | 3/8 = 37,5% | 9 | authenticate/login_user/verify_signature có thể là cơ chế phòng vệ đúng |

Cả bốn dưới ngưỡng audit 0,50 với ít nhất năm lần báo trên mẫu dương train. Không suy luận mọi finding sai lớp là báo nhầm thật; quyết định còn dựa trên việc rule thiếu cơ chế lỗ hổng cụ thể. Không thay bằng các rule mới chỉ để lấy lại số lượng cảnh báo.

Nguồn rule được giữ trong `rules_disabled/`, tăng rule_version và thêm `metadata.disabled_v460`. Fixture gốc của các file bị ảnh hưởng được giữ trong `tests_disabled/`, đồng thời có snapshot đầy đủ v4.5.0. Đã gỡ 12 assertion của rule nghỉ khỏi bộ test đang chạy; 287 assertion còn lại đều đạt. Đã kiểm tra bốn ID không có trong bundle và 79 rule còn lại không đổi logic, chỉ tăng ruleset_version.

## Số đo trước/sau trên nhãn v2.2 nguyên trạng

Đã quét lại toàn bộ bundle v4.6.0 trên cả train và validation bằng cùng wrapper/normalizer trước đây. Baseline v4.5.0 dùng kết quả đã lưu và xác minh ở R4. Tập test và bốn ứng dụng mục tiêu không được dùng.

| Chỉ số | v4.5.0 | v4.6.0 | Thay đổi |
|---|---:|---:|---:|
| Train: mẫu âm có finding bất kỳ | 1.135/5.757 = 19,72% | 1.008/5.757 = 17,51% | Giảm 127 mẫu |
| Val: mẫu âm có finding bất kỳ | 182/854 = 21,31% | 161/854 = 18,85% | Giảm 21 mẫu |
| Train: mẫu dương có finding đúng lớp | 836/3.042 = 27,48% | 805/3.042 = 26,46% | Giảm 31 mẫu |
| Val: mẫu dương có finding đúng lớp | 144/391 = 36,83% | 135/391 = 34,53% | Giảm 9 mẫu |

**Có đánh đổi độ phủ**, không được gọi đây là cải thiện toàn diện về accuracy/precision. `train_lost_label_coverage.csv` và `val_lost_label_coverage.csv` liệt kê các mẫu mất finding đúng lớp theo nhãn hiện tại để truy vết. Các con số không dùng nhãn đã được AI “sửa”.

Tầng **high giữ nguyên**: train bắt đúng lớp 169 mẫu dương và báo 80 mẫu âm; val bắt đúng lớp 19 mẫu dương và báo 13 mẫu âm. Hai rule audit PHP mới ở v4.5.0 vẫn được giữ. Cấu hình model/Gate không bị thay đổi.

## Khóa phiên bản

- Train SHA-256: `dbf9cdf24edacda0f3af67115d5b3ecae800ba6aa05c54ae02db4411c496f77f`.
- Val SHA-256: `f59df7639a39c2fa72168f6fe2de01add4b850cde9839c01e0b2c7786e4ce305`.
- Baseline v4.5.0 bundle SHA-256: `ae594c87d57d1b2f769e86ff87391dc50b628019db5a5bc3275c3341f16c7e07`.
- v4.6.0 bundle SHA-256: `0871de4db25128f05b71ae863dd1695aeee1daa1819a9d230b91abf7cf605c57`.
- 79 active rule, 287/287 tests; `regression_passed: true`; verify đạt. Còn 27 cảnh báo lịch sử không chặn phát hành, trước đó là 30.
- Không có Git repository trong workspace main; đã bảo toàn snapshot trước khi sửa. Không commit hoặc push sang repo CI.

## Tệp bàn giao

- `BANG_DUYET_11_MAU.csv`: bảng tiếng Việt để người duyệt ghi quyết định.
- `task1_review.csv`: bằng chứng, nguồn, hash từng mẫu và trường ký duyệt.
- `task1_details.json`: vị trí và ngữ cảnh query trong mẫu; chỉ dùng đọc nội bộ, không phải nhãn thay thế.
- `candidate_exclusions.json`: đề xuất bảy ID cần giữ ngoài bộ dữ liệu đã được xác minh trong tương lai, chưa áp dụng.
- `disabled_decisions.json`: lý do tắt và số assertion nghỉ.
- `comparison_v450_v460.json`: số đo kiểm tra trước/sau.
- `v460/`: kết quả quét train/val theo ID, không chứa code nguồn dataset.
- Snapshot: `../../archive/semgrep_v4.5.0_before_task12_2026-10-26.zip`.

## Tái lập từ main

```powershell
.\.venv\Scripts\python.exe security-config\semgrep\tools\ruleset.py all
.\.venv\Scripts\python.exe security-config\semgrep\tools\ruleset.py verify
.\.venv\Scripts\python.exe security-config\semgrep\tools\evaluate_supplement_v22.py --split train --config security-config\semgrep\semgrep.yml --out security-config\semgrep\reports\task12_v22_2026-10-26\v460
.\.venv\Scripts\python.exe security-config\semgrep\tools\evaluate_supplement_v22.py --split val --config security-config\semgrep\semgrep.yml --out security-config\semgrep\reports\task12_v22_2026-10-26\v460
```

## Điều chưa chắc chắn

Rà kỹ thuật đã hoàn tất cho 11 ca, nhưng xác nhận nhãn cuối cùng chưa hoàn tất cho các ca HOLD/cách ly và chưa có chữ ký người duyệt. Không đánh đồng “chưa tìm được đường khai thác” với “an toàn”. Bản v2.2 nguyên gốc được giữ để tái lập. Việc chốt nhãn chắc chắn hơn cần bằng chứng caller/nguồn dữ liệu và môi trường lịch sử; không nên giải quyết bằng thêm tên hàm vào whitelist chung.
