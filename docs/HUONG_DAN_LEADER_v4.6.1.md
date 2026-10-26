# Semgrep v4.6.1 — sẵn sàng đưa vào hạ tầng (P2)

Ngày 26/10/2026 · Semgrep **1.181.0** · taxonomy 0.3.0 · **79 rule**, **306/306** test đạt, `verify` đạt · bundle sha256 `bff761dd3726fa3a094109e30dc3d6f62612254d4cf135e3a1e627ac2b863986`

Gói này thay cho các gói v4.6.0. Đọc theo thứ tự: mục 1 → 2 → 5 (quyết định cần chốt).

## 1. Thay đổi so với v4.6.0: tầng high không còn regex thô

Quét thử repo thật cho 1 finding high sai: rule regex `team.sql-injection` khớp **chuỗi văn bản** chứa code mẫu. Finding high vào gate nên có thể chặn build sai. Đã viết lại bằng pattern AST: `team.sql-injection`, `team.path-traversal`, `team.hardcoded-credentials`, `team.hardcoded-auth-header`; bỏ nhánh regex của `team.os-command-injection`.

| Chỉ số (nhãn v2.2 nguyên trạng) | Train v4.6.0 → v4.6.1 | Val v4.6.0 → v4.6.1 |
|---|---|---|
| Mẫu dương bắt đúng lớp | 805 → 791 | 135 → 134 |
| …tầng high | 169 → 157 | 19 → 17 |
| Mẫu âm bị báo | 1.008 → 1.001 | 161 → 161 |
| …tầng high | 80 → 73 | 13 → 13 |
| Repo thật: finding high sai | 1 → **0** | |

14 mẫu train mất đều là Hardcoded Python (CredData), phần lớn credential trong comment/doctest hoặc đoạn cắt không parse được. Chi tiết: `security-config/semgrep/reports/regex_ast_v461_2026-10-26/README.md`.

Còn 7 rule regex, **đều tầng audit** (không chặn build). Cảnh báo kiểm tra: 27 → 22 (còn lại: tên lớp Auth cũ, CWE-916/384, 7 regex audit).

## 2. Script quét repo cho CI: `security-config/semgrep/tools/scan_repo.py`

Theo `docs/semgrep_tool.md` mục 2.2–2.3:

```powershell
.\.venv\Scripts\python.exe security-config\semgrep\tools\scan_repo.py --repo <repo> --out semgrep-results.json --scope-out scope.json
```

1. Kiểm tra cấu hình: Semgrep 1.181.0, `ruleset.py verify`, `taxonomy.yml`. Sai → **mã thoát 2**, không quét (nút "Kiểm tra cấu hình và môi trường SAST" của P1).
2. Chọn phạm vi: 4 ngôn ngữ, loại theo `security-config/semgrep/.semgrepignore`, loại file có dòng trung bình > 300 ký tự (như phía CodeBERT). `scope.json` = danh sách file để CodeBERT dùng **cùng phạm vi**.
3. Trạng thái parse từng file: `ok | partial | failed | not_scanned`.
4. Hậu xử lý: lớp theo taxonomy (đổi tên cũ `AUTHENTICATION_WEAKNESS` → `INSECURE_AUTHENTICATION` ở đầu ra), kiểm CWE thuộc lớp (`--strict` để biến lệch thành lỗi), bỏ lớp ngoài 6 nhóm, gắn high/audit, gộp trùng.
5. Mã thoát 0 dù có finding (Gate quyết định); 3 = Semgrep lỗi khi quét.

Mẫu đầu ra thật: `reports/p2_demo_2026-10-26/semgrep-results.json` (repo AI-WhiteSec-Ci, 15 file, 4,1 giây) và `reports/regex_ast_v461_2026-10-26/p2_demo_semgrep-results.json` (v4.6.1: 0 high, 189 audit).

**Nhận xét từ lần quét thật:** 140/189 finding audit là `team.js.xss-html-concat` trên code dashboard tự ghép HTML. Tầng audit chỉ nên **ghi nhận**, không chặn build (đúng bản nháp gate trong `taxonomy.yml`).

## 3. Đề xuất: đóng băng tính năng rule

Không chạy theo recall trên v2.2 nữa: 93% nhãn UNREVIEWED; R4 chỉ thêm 24/3.042 mẫu train và 0 trên val; recall high thấp vì mẫu là hàm cắt rời. Phần Semgrep chuyển sang tích hợp (job GitLab CI, ghép P4).

## 4. R1 (từ gói trước, giữ lại để tiện đọc)

### Chồng lấn dữ liệu chỉnh rule với test v2.2

Script `33_overlap_keys.py compare` chỉ đọc khóa của test, không mở nội dung mẫu.

| Khóa | Mẫu test v2.2 bị trùng / 1.322 |
|---|---|
| repo | **956 (72%)** |
| code giống hệt (chuẩn hóa khoảng trắng) | **449 (34%)** |
| commit / CVE | 0 (test v2.2 không có cột này) |
| 4 ứng dụng mục tiêu | 0 |

Dữ liệu chỉnh rule bị trùng: 2.403 dòng, thực chất 1.149 mẫu khác nhau; phần lớn từ train v5/a01.
Báo cáo `Bao_cao_so_sanh_dataset_2026-10-26.md` cũng ghi nhận cùng vấn đề.

**Hệ quả:** test v2.2 không phải phép đo độc lập cho Semgrep. Đề xuất ở R5 báo hai kết quả: toàn bộ test, và test bỏ 956 mẫu thuộc repo trùng (còn 366 mẫu).

File: `security-config/semgrep/reports/r1_overlap_v22_2026-10-25.{md,csv}`, `reports/r1_overlap_rules_v22.md`.

### Đo nền v4.3.1 trên train/val v2.2 (mốc so sánh cho v4.4–v4.6)

| Chỉ số | Train | Val |
|---|---:|---:|
| Parse ok | 0,94 | 0,91 |
| Recall high | 0,06 | 0,06 |
| Recall high+audit | 0,27 | 0,37 |
| Báo nhầm mẫu âm (bất kỳ / high) | 0,20 / 0,02 | 0,21 / 0,02 |

Sau v4.6.0 (theo `task12_v22_2026-10-26/README.md`): mẫu âm có finding train 17,5%, val 18,9%; mẫu dương bắt đúng lớp train 26,5%, val 34,5%; tầng high không đổi.

File: `r1_tong_hop_v22_2026-10-25.md`, `r1_baseline_v22_{train,val}_2026-10-25.*`, `r1_fn_v22_train_2026-10-25.csv`; script `34_baseline_v22.py`, `run_r1_v22.bat`.

## 5. Quyết định cần leader chốt

1. Đổi tên lớp Auth thành `INSECURE_AUTHENTICATION` trong mọi rule (một đợt, v4.7.0, rồi đóng băng). Đầu ra `scan_repo.py` đã dùng tên mới.
2. CWE-916 và CWE-384 thuộc lớp nào.
3. Gate: xác nhận tầng audit chỉ ghi nhận, không chặn build; ngưỡng báo nhầm tầng audit.
4. Xử lý chồng lấn test v2.2 (mục 4) và thời điểm R5.
5. `.semgrepignore` đang trộn mục chung (`node_modules/`, `vendor/`) với mục riêng của đồ án (`data/`, `models/`, `security-config/semgrep/tests/`). Khi quét repo khác, `data/` có thể loại nhầm code thật → đề xuất tách hai file, thống nhất với phía CodeBERT.
6. Runner GitLab CI, nơi lưu model; người duyệt cho `BANG_DUYET_11_MAU.csv`.

## Kiểm tra trước khi dùng

```powershell
.\.venv\Scripts\semgrep.exe --version
.\.venv\Scripts\python.exe security-config\semgrep\tools\ruleset.py verify
```
