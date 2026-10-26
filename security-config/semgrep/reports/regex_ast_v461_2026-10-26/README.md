# v4.6.1 · Viết lại 5 rule regex tầng high bằng pattern AST

Ngày 26/10/2026. Semgrep 1.181.0, taxonomy 0.3.0, dataset v2.2 (train/val; không đọc test, không dùng 4 ứng dụng mục tiêu). Snapshot trước khi sửa: `archive/semgrep_v4.6.0_before_regex_ast_2026-10-26.zip`.

## Lý do

Quét thử repo thật (`p2_demo_2026-10-26`, repo AI-WhiteSec-Ci) cho **1 finding high sai**: `team.sql-injection` (regex) khớp một **chuỗi văn bản** chứa code mẫu trong `tests/test_dashboard.py:55`. Regex so khớp chữ thô nên không phân biệt code với chuỗi/comment. Finding high đi vào gate → có thể chặn build sai. Đây là nhóm "regex không có `paths.include`" đã cảnh báo từ v4.3.

## Thay đổi (79 rule; logic rule khác không đổi)

| Rule | rule_version | Thay đổi |
|---|---|---|
| `team.sql-injection` | 1.1.0 → 1.2.0 | AST: `execute/executemany/executescript/raw/extra/text` nhận chuỗi ghép `%`, `+`, `.format()` hoặc f-string có biến |
| `team.path-traversal` | 1.1.0 → 1.2.0 | AST: `open/Path/send_file/send_from_directory/FileResponse/serve_file/join` nhận đối số chứa `request.<args/form/values/json/files/GET/POST/...>` |
| `team.hardcoded-credentials` | 1.1.0 → 1.2.0 | AST: gán chuỗi hằng (≥ 4 ký tự, không khoảng trắng) cho biến / thuộc tính / tham số có tên / khóa dict có tên kiểu password, secret, api_key, access/auth_token, private_key |
| `team.hardcoded-auth-header` | 1.1.0 → 1.2.0 | Nhánh regex → AST: `"Authorization": "Bearer/Basic/Token <≥ 8 ký tự>"` trong dict hoặc gán `headers["Authorization"]` |
| `team.os-command-injection` | 1.2.0 → 1.3.0 | Bỏ nhánh regex `subprocess...shell=True` (đã có pattern AST tương đương) |

Test: thêm positive cho dạng mới và negative cho code nằm trong chuỗi; 306/306 đạt, `verify` đạt, unit test 55/55.

## Số đo trước/sau (cùng công cụ `evaluate_supplement_v22.py`, baseline = v4.6.0)

| Chỉ số | Train v4.6.0 | Train v4.6.1 | Val v4.6.0 | Val v4.6.1 |
|---|---:|---:|---:|---:|
| Mẫu dương bắt đúng lớp | 805 | 791 (−14) | 135 | 134 (−1) |
| Mẫu dương bắt đúng lớp tầng high | 169 | 157 (−12) | 19 | 17 (−2) |
| Mẫu âm có finding | 1.008 | 1.001 (−7) | 161 | 161 |
| Mẫu âm có finding high | 80 | 73 (−7) | 13 | 13 |
| Repo thật AI-WhiteSec-Ci: finding high | 1 (sai) | **0** | | |

- Train mất 14 mẫu, **đều là HARDCODED_CREDENTIALS Python nguồn CredData**: credential nằm trong comment/doctest (`# add: {"password": ...}`, `>>> ... client_secret='secret'`), gán tuple (`login, password = '...', '...'`), hoặc đoạn ±5 dòng parse dở (6 mẫu `partial`). Một mẫu mất là `self.__pwd = 'C:\\'` (đường dẫn, không phải mật khẩu).
- Val mất 1 mẫu Hardcoded và 1 mẫu SQL_INJECTION ở tầng high (không xem code val để chỉnh).
- Không có mẫu dương nào được thêm; không có mẫu âm nào mới bị báo high.

## Đánh đổi cần leader biết

AST không thấy credential trong comment/docstring. Với Semgrep ở vai trò "high phải chính xác", đây là đánh đổi chấp nhận được: −12 mẫu high trên train đổi lấy hết báo sai high trong chuỗi khi quét repo thật. Phía CodeBERT vẫn nhìn được nội dung comment.

## Còn lại

7 rule regex không có `paths.include` đều ở tầng **audit** (không chặn build): `team.java.sqli-concat`, `team.java.xss-html-concat`, `team.js.sqli-string`, `team.js.xss-html-concat`, `team.php.sqli-string`, `team.sql-string-building`, `team.xss-html-string-building`. Hai rule PHP template (`regex` + `paths.include`) hợp lệ theo 5.2.

## Điều chưa chắc chắn

- Số đo dựa trên nhãn v2.2 nguyên trạng (93% UNREVIEWED).
- Mẫu CredData là đoạn ±5 dòng; tỉ lệ parse thấp hơn file thật nên số Hardcoded trên dataset có thể thấp hơn khi quét repo.
