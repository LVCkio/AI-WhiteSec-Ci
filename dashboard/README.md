# Dashboard AI-WhiteSec-CI

Dashboard chạy trên máy (local), chỉ hiển thị **kết quả thực nghiệm thật** của dự án: Semgrep CE và CodeBERT chạy song song, gộp ở Compare, rồi Security Gate ra quyết định. Dashboard không có dữ liệu minh họa, không chạy scanner hay mô hình và không sửa file nào. Nó chỉ đọc các file JSON mà pipeline đã tạo ra.

## Chạy

Nhấp đúp `run_dashboard.bat` trong thư mục `main`. Cách khác là chạy lệnh:

```
.venv\Scripts\python.exe dashboard\server.py
```

Trình duyệt sẽ tự mở `http://127.0.0.1:8765/`. Nhấn Ctrl+C trong cửa sổ đen để dừng.

- Chỉ dùng thư viện chuẩn của Python, không cần cài thêm gì (cũng không cần Node hay internet). Nếu có PyYAML (có sẵn trong `.venv` cùng Semgrep) thì dùng để đọc rule, nếu không thì tự tách rule.
- Server chỉ nghe trên `127.0.0.1`, nên máy khác trong mạng không truy cập được.
- Khi có file kết quả mới, bấm **Làm mới** (hoặc quay lại tab trình duyệt), dashboard sẽ tự đọc lại.
- Đổi cổng: `dashboard\server.py --port 9000`. Không tự mở trình duyệt: thêm `--no-browser`.

## Sáu màn hình

| Màn hình | Nội dung | Nguồn dữ liệu |
|---|---|---|
| **Tổng quan** | Số đơn vị BLOCK / REVIEW; lỗ hổng thật bị chặn và hàm an toàn bị chặn nhầm (theo ground truth); luồng xử lý của cấu hình; kết quả từng ứng dụng; trạng thái Compare; cảnh báo ưu tiên | `reports/targets/*_scan_*.json`, `*_eval_*.json` |
| **Cảnh báo bảo mật** | Lọc theo quyết định, lớp, ngôn ngữ, trạng thái Compare, ground truth (đúng lớp / sai lớp / báo nhầm / bỏ sót). Mỗi cảnh báo có: lý do Gate (quy tắc `policy` đã áp dụng), finding Semgrep (rule, tầng high/audit, dòng), xác suất 6 lớp của CodeBERT, `p_vulnerable` so với ngưỡng, CWE/OWASP, gợi ý khắc phục, đoạn mã nguồn. Xuất được CSV | như trên, cộng mã nguồn trong `targets/<app>/scan_src` |
| **Đánh giá mô hình** | 6 tab: CodeBERT 6 lớp (macro-F1, KTC, theo ngôn ngữ, ma trận nhầm lẫn, ngôn ngữ × lớp, đường học, lưới C01) · Verifier (ROC-AUC, theo ngôn ngữ) · Security Gate trên val cặp trước/sau vá (Semgrep đơn lẻ so với Semgrep + AI, quét ngưỡng) · Ứng dụng mục tiêu (tổng 4 app, theo app, tiến trình các cấu hình) · Ruleset Semgrep (ngôn ngữ × lớp, bản mới so với bản trước) · Trước/sau fine-tune (C06) | `models/<model>/run_info.json`, `reports/gate_eval_val_*.json`, `reports/j01_val*.json`, `reports/rule_metrics_v*_val.json`, `reports/pretrain_vs_finetune_*_val.json`, `reports/c01_grid.csv` |
| **Giám sát lượt quét** | Từng lần chạy `scan.py`: cấu hình, SHA-256 ruleset, thời gian từng luồng (song song so với nối tiếp), quyết định, đối chiếu ground truth | `scan.py` JSON |
| **Cấu hình & Rule** (theo yêu cầu của thầy) | 5 tab: **Phiên bản & kiểm thử** (scan.py, ruleset + SHA-256 + Semgrep ghim, mô hình + SHA dữ liệu train/val, verifier, Gate; phiên bản dữ liệu; các tập test: test chính J01 (đóng băng/đã dùng), test theo thời gian E05, 270 test của rule, unit test) · **Ngưỡng & chính sách** (ngưỡng verifier và cách chọn, ngưỡng lớp, `block_min_severity`, tầng high/audit, 512 token, siêu tham số, điểm ưu tiên; bảng policy và chế độ suy giảm) · **Rule Semgrep** (toàn bộ rule của nhóm: lọc theo ngôn ngữ/lớp/tầng/kiểu, mỗi rule có nội dung YAML, metadata, test, số đúng lớp train/val, TC5; rule đã tắt và lý do) · **Tiêu chí chọn rule** (TC1–TC8) · **Dữ liệu & ground truth** (ngôn ngữ × lớp theo tập, nguồn dữ liệu, ánh xạ lớp ↔ CWE/OWASP, ground truth 4 ứng dụng) | `security-config/semgrep/{semgrep.yml, ruleset-manifest.json, reports/rule_test_results.json, rules_disabled/, TIEU_CHI_CHON_RULE.md}`, `reports/rule_metrics_*.csv`, `reports/rule_pairs_diff_*.csv`, `data_versions/*/manifest.json` + CSV (chỉ đếm), `rules/vuln_metadata.json`, `reports/unittest_log.txt`, `targets/*/ground_truth.json` |
| **So sánh lượt quét** | Hai lượt của cùng một ứng dụng/repo (ví dụ ruleset v4.1 → v4.2): đơn vị mới cảnh báo, không còn cảnh báo, đổi mức, đổi lớp; ý nghĩa theo ground truth (bắt thêm lỗ hổng / thêm báo nhầm / bỏ sót mới). Xuất được JSON | `scan.py` JSON |

Ô **Cấu hình pipeline** ở đầu trang chọn bộ kết quả để xem. Cấu hình đánh dấu ★ là cấu hình hiện tại, tức là khớp đồng thời `models/pipeline_config.json`, `models/gate_config.json` và `RULESET_VERSION` trong `security-config/semgrep/tools/ruleset.py`. Các cấu hình cũ (D05, C03 có Bandit, Semgrep v4.1…) vẫn xem được để so sánh.

## Thêm lượt quét của commit / CI

Đặt JSON của `scan.py` vào `reports/scans/`, rồi bấm Làm mới:

```
.venv\Scripts\python.exe scan.py --repo <repo> --commit <sha> --json reports\scans\<tên>.json --sarif reports\scans\<tên>.sarif
```

Dashboard chỉ đọc các bản quét theo kiến trúc song song (có `all_units`). Các file quét theo kiến trúc cũ (SAST làm cổng) được bỏ qua.

## Khác gì so với bản tham khảo `AI-WhiteSec-dashboard-reference`

Bản tham khảo được viết cho một hệ thống khác (Checkmarx + Gateway). Bản này **giữ** giao diện tối, bố cục năm màn hình, font và icon chạy offline, cách đối chiếu hai lượt quét và cách tách bạch rõ “không còn ghi nhận” với “đã sửa”. Phần **đã bỏ** vì không khớp với dự án:

- Checkmarx, SARIF upload, adapter Checkmarx: dự án dùng Semgrep CE chạy trong `scan.py`.
- FastAPI Gateway, dịch vụ CodeBERT riêng, PostgreSQL/SQLite audit, Docker Compose, lease worker, API schema 2.0: pipeline của dự án là một CLI (`scan.py`) chạy trong CI và ghi ra JSON/SARIF.
- API key, `allow_deploy`, `release_approved`: không cần với dashboard chỉ đọc chạy trên máy.
- Dữ liệu minh họa (fixture): theo yêu cầu của nhóm, chỉ hiển thị số thực nghiệm để không lẫn với kết quả bảo vệ.
- Nhãn 6 lớp “INSECURE_AUTHENTICATION” của bản tham khảo: đổi theo nhãn thật của dự án (`AUTHENTICATION_WEAKNESS`, …).

Phần **thêm mới** cho đúng với dự án:

- Ground truth của 4 ứng dụng mục tiêu: mỗi cảnh báo được đánh dấu đúng lớp, sai lớp, báo nhầm hoặc bỏ sót.
- Lý do Gate tính theo đúng `policy` của từng lượt quét.
- Verifier `p_vulnerable` hiển thị cùng ngưỡng đang dùng.
- Màn đánh giá dùng số thật trên tập val (tập test giữ cho J01).
- So sánh cấu hình theo ground truth.
- Xem mã nguồn của đơn vị bị cảnh báo.

## An toàn

- Dashboard chỉ đọc file trong `main/`, không ghi file nào.
- `/api/source` chỉ trả đoạn mã của **file nằm trong chính lượt quét đó** (tối đa 400 dòng mỗi lần) và chặn đường dẫn `..`.
- Server kiểm tra header `Host` (chống DNS rebinding) và gửi CSP: chỉ nạp script/font từ chính server.
- Mọi chuỗi lấy từ dữ liệu đều được escape trước khi hiển thị.

## Kiểm thử

```
.venv\Scripts\python.exe -m unittest tests.test_dashboard -v
```

Bộ test dựng dữ liệu giả lập rồi kiểm tra: bỏ bản quét cũ, chọn đúng cấu hình hiện tại, khớp ground truth, đổi NaN thành null, lấy số Gate tại ngưỡng đang dùng, chặn Host lạ, chặn path traversal, chỉ trả mã nguồn của file đã quét. Test cũng dựng thử dữ liệu thật của dự án.
