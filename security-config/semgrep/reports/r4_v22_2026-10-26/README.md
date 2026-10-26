# R4 — Bổ sung rule từ train v2.2, ruleset v4.5.0

Ngày: 26/10/2026. Semgrep CE 1.181.0, taxonomy 0.3.0. 83 rule; regression **299/299 đạt**, `ruleset.py verify` đạt.

## Kết quả và giới hạn

Đã bổ sung hai rule PHP ở tầng **audit**, sau khi xem code train và cặp trước/sau sửa. Giữ nguyên nhãn dataset, model và Gate. 81 rule cũ chỉ đổi `metadata.ruleset_version`; đã so sánh cấu trúc từng rule với snapshot v4.4.1 để xác nhận không đổi logic.

| Rule mới | Khớp mẫu dương train | Đúng lớp theo nhãn hiện tại | Mẫu dương bắt thêm so với v4.4.1 | Mẫu âm bị báo |
|---|---:|---:|---:|---:|
| `team.php.audit.query-single-dynamic-where` | 20 | 20 | 14 | 9 |
| `team.php.audit.gitphp-unescaped-argument` | 10 | 10 | 10 | 0 |
| Tổng | 30 | 30 | 24 | 9 |

Các tỷ lệ 20/20 và 10/10 chỉ là **đúng lớp trên mẫu được gán dương**, không phải precision được thẩm định độc lập. Trên validation, cả hai rule mới **không có finding**: chưa có dữ liệu để kết luận khả năng tổng quát hóa, không được coi là đạt precision 100%.

## Đối chiếu trước/sau

| Chỉ số toàn bộ ruleset | v4.4.1 | v4.5.0 |
|---|---:|---:|
| Train: mẫu dương bắt đúng lớp | 812/3.042 (26,69%) | 836/3.042 (27,48%) |
| Train: mẫu âm có finding bất kỳ | 1.130/5.757 (19,63%) | 1.135/5.757 (19,72%) |
| Val: mẫu dương bắt đúng lớp | 144/391 (36,83%) | 144/391 (36,83%) |
| Val: mẫu âm có finding bất kỳ | 182/854 (21,31%) | 182/854 (21,31%) |

Hai rule báo tổng cộng chín mẫu âm train; bốn mẫu vốn đã bị bộ cũ báo, nên toàn bộ ruleset tăng thêm năm mẫu âm có finding. Không tự động đổi chín nhãn này thành dương.

Phương pháp đo: chạy baseline v4.4.1 mới trên đủ 8.799 train và 1.245 validation, rồi chạy riêng hai rule cuối cùng trên chính các mẫu đó bằng cùng normalizer/wrapper của `34_baseline_v22.py` và Semgrep 1.181.0. Kết quả v4.5.0 toàn bộ được tính bằng hợp kết quả theo ID mẫu, sau khi xác minh 81 rule cũ không đổi logic. Đây không phải một lượt quét lại toàn bộ bundle v4.5.0 trên dataset. Bộ test hồi quy thì đã chạy toàn bộ 83 rule.

## Vì sao chọn hai dạng này

### SQL — query_single có WHERE động

API này nhận WHERE ở tham số thứ ba, nên các rule chỉ theo dõi `query`/`exec`/`prepare` bỏ sót. Các cặp train chuyển nối chuỗi sang named placeholders và bindings.

Ví dụ đã xem code và diff:

- `cvefixes-154174992494703`: `authenticate_by_email`; WHERE ghép email chuyển thành `website = :wid AND email = :email` cùng bindings.
- `cvefixes-242885272355694`: `find_by_reference`; reference/website chuyển sang bindings.
- `cvefixes-141303450623401`: tạo username; hai truy vấn WHERE động chuyển sang placeholders.

Rule chỉ xét receiver giống DB và tham số WHERE. Literal/bindings không bị báo; giá trị được dùng qua `intval`, ép kiểu int hoặc `floatval` bên trong WHERE được bỏ qua. Có negative test cho truy vấn chỉ ghép số và positive test cho câu WHERE vừa có số đã ép kiểu vừa có email chưa xử lý.

Không mặc nhiên công nhận `protect()` là sai hoặc an toàn khi chưa xem triển khai trong ngữ cảnh. Rule ở audit vì chỉ chứng minh SQL động cần kiểm tra. Với 20 bản trước sửa được báo đúng lớp và có cặp, ba bản sau sửa vẫn bị rule báo; các hàm có thể chứa nhiều truy vấn nên cần rà đúng finding, không kết luận cả bản vá còn lỗ hổng chỉ từ con số này.

### OS command — danh sách tham số GitPHP

Các mẫu train gọi executor riêng `Execute(projectPath, GIT_*, args)`. Bản vá thêm `escapeshellarg` khi đưa giá trị vào mảng arguments. Rule AST tập trung vào **dòng append**, rồi kiểm tra danh sách đó được đưa vào executor phù hợp; không gán mọi API tên Execute thành shell sink.

Ví dụ đã xem code và diff:

- `cvefixes-120669059115154`: `Load`, thêm quote cho `GetHash()`.
- `cvefixes-161643041907257`: `LoadHashPaths`, cùng cơ chế.
- `cvefixes-168834373219513`: `LoadContainingTag`, quote hash trước executor.
- `cvefixes-211258898802627`: `ExpandHash`, quote abbreviated hash.
- `cvefixes-226672440264717`: `SearchFileContents`, thay tự bọc chuỗi/addslashes bằng quote phù hợp.

Rule bỏ qua quote ngay tại append, các giá trị số/hằng và danh sách bị thay thế trước khi gọi executor. Bộ test có trường hợp quote, prefix nối chuỗi đã quote, ép kiểu số, executor không liên quan và lệnh ngoài `GIT_*`. Cả 10 bản trước sửa bị báo; **0/10** bản sau sửa tương ứng bị báo.

Rule này là kiểm tra cấu trúc AST có phạm vi GitPHP, không phải chứng minh dữ liệu đến từ request hay một phân tích luồng đầy đủ. Biến đã được làm sạch từ trước hoặc wrapper khác có thể cần rà thêm. Quoting shell argument cũng không tự chứng minh không còn option injection hay lỗi khác.

## Đã xử lý lo ngại nhãn thế nào trước khi viết rule

- Không gộp v5_1_e03 vào train; không dùng checkpoint CodeBERT hay các F1 khác bài toán để chọn rule.
- Chỉ chọn mẫu train có API/sink cụ thể và diff liên quan; không viết rule để khớp đơn thuần một hàm đang mang nhãn XSS/Path Traversal.
- Kiểm tra cả mẫu âm train mà rule ứng viên báo. Đã nhận diện và lọc nguyên nhân chung: các câu WHERE chỉ ghép số đã ép kiểu. Số mẫu âm bị rule mới báo giảm từ 17 xuống 9.
- Đối chiếu với AI-review 204 mẫu đã có: ba mẫu trùng danh sách này, gồm một CORRECT và hai UNSURE; không có mẫu bị đánh dấu WRONG trong tập finding của hai rule. Hai UNSURE vẫn được giữ trong hàng chờ, không dùng chúng làm bằng chứng nhãn chắc chắn.
- Bằng chứng kiểm tra code/diff trong vòng này do AI thực hiện; chưa phải human-review độc lập. Xem `train_evidence_and_review.csv`: 39 mẫu có finding của rule mới, gồm 30 mẫu gán dương và chín mẫu gán âm; có trạng thái cần review và ý kiến AI trước đó.
- Hai rule đủ tối thiểu ba mẫu train có dạng tương ứng để thử bổ sung theo TC2. Ngưỡng đúng lớp TC4 trên train đạt cho audit; validation không có finding nên trạng thái vẫn **chưa đủ dữ liệu**.

## Khóa phiên bản và tệp

- Dataset v2.2 train SHA-256: `dbf9cdf24edacda0f3af67115d5b3ecae800ba6aa05c54ae02db4411c496f77f`.
- Dataset v2.2 val SHA-256: `f59df7639a39c2fa72168f6fe2de01add4b850cde9839c01e0b2c7786e4ce305`.
- DATA_CARD SHA-256: `bc43638e1066c3a2b1ced5b82a52f9be37eae50296aed629bdfc04ad25cea9b1`.
- Baseline bundle v4.4.1 SHA-256: `55b85d57e86d81f63bb21b0e843ef6b12240d7f1bf08d8e78c5ee56c5d766dae`.
- Bundle v4.5.0 SHA-256: `ae594c87d57d1b2f769e86ff87391dc50b628019db5a5bc3275c3341f16c7e07`.
- `comparison.json`: số đo và bảng ngôn ngữ × lớp trước/sau.
- `train_combined_samples.csv`, `val_combined_samples.csv`: đối chiếu theo ID, không chứa code.
- `baseline_v441/`: baseline quét lại; `final_v450/`: số đo cuối cho phần bổ sung.
- `added_rules_v450.yml`: snapshot hai rule được đo, đã đối chiếu khớp nguồn rule hiện tại.
- `train_evidence_and_review.csv`: metadata để người duyệt truy vết nhãn; không phải nhãn thay thế.
- Snapshot nguồn cũ: `../../archive/semgrep_v4.4.1_before_r4_2026-10-26.zip`.

Workspace main không có Git repository, như manifest trước đó đã ghi. Đã lưu snapshot trước khi sửa; không tạo lịch sử commit hoặc phát hành thay cho repo CI.

## Tái lập từ thư mục main

```powershell
.\.venv\Scripts\python.exe security-config\semgrep\tools\ruleset.py all
.\.venv\Scripts\python.exe security-config\semgrep\tools\ruleset.py verify
.\.venv\Scripts\python.exe security-config\semgrep\tools\evaluate_supplement_v22.py --split train --config security-config\semgrep\reports\r4_v22_2026-10-26\added_rules_v450.yml --out security-config\semgrep\reports\r4_v22_2026-10-26\final_v450 --baseline security-config\semgrep\reports\r4_v22_2026-10-26\baseline_v441\train_samples.csv
.\.venv\Scripts\python.exe security-config\semgrep\tools\evaluate_supplement_v22.py --split val --config security-config\semgrep\reports\r4_v22_2026-10-26\added_rules_v450.yml --out security-config\semgrep\reports\r4_v22_2026-10-26\final_v450 --baseline security-config\semgrep\reports\r4_v22_2026-10-26\baseline_v441\val_samples.csv
```

Công cụ chỉ nhận split train/val. Không gọi registry, không dùng Bandit. Tham khảo cú pháp từ [tài liệu pattern của Semgrep](https://semgrep.dev/docs/writing-rules/pattern-syntax/); việc chấp nhận rule dựa trên chạy thật bằng phiên bản đã ghim.

## Điều chưa chắc chắn

1. Nhãn v2.2 vẫn chưa được xác minh đầy đủ. Chín mẫu âm và hai mẫu có ý kiến AI UNSURE cần người duyệt; không có thay đổi nhãn tự động.
2. Hai rule mới phụ thuộc hai API/framework cụ thể. Chưa có finding validation, chưa chứng minh hiệu quả trên dự án độc lập.
3. 30 cảnh báo kiểm tra cũ vẫn tồn tại, gồm tên Auth cũ, mapping CWE chờ xác nhận và regex của rule lịch sử. Không phát sinh cảnh báo mới từ hai rule này.
4. Chưa xử lý toàn bộ nợ chất lượng của các rule cũ, chưa nâng rule mới lên high, chưa đo model hoặc chấm Gate.
5. Trong vòng bổ sung này không đọc/quét test hay bốn ứng dụng mục tiêu. Chồng lấn đánh giá lịch sử được ghi nhận trước đây vẫn phải được xử lý trong protocol đánh giá cuối.
