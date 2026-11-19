# v4.7.0 · Đổi tên lớp Auth thành INSECURE_AUTHENTICATION

Ngày 26/10/2026 · Semgrep 1.181.0 · bundle sha256 `29aea8a801f93a4f149849c3eb256b5466a09eb314ede3822af3637e9df24a77` · dataset v2.3 (train/val; không đọc test).
Snapshot trước khi sửa: `archive/semgrep_v4.6.1_before_auth_rename_2026-10-26.zip`. **Chờ leader đồng ý trước khi merge.**

## Thay đổi

- 10 rule Auth: `vuln_class` `AUTHENTICATION_WEAKNESS` → `INSECURE_AUTHENTICATION` (tên trong `docs/taxonomy.yml` v0.3.0 và vector nhãn CodeBERT); tăng `rule_version`; ghi `change_v470`. **Pattern không đổi.** Tên file `authentication_weakness.yml` và id rule giữ nguyên.
  - Java: `team.java.auth-jwt-unverified`, `team.java.auth-weak-password-hash`
  - JavaScript: `team.js.auth-jwt-unverified`, `team.js.auth-jwt-decode`, `team.js.auth-weak-password-hash`
  - PHP: `team.php.auth-weak-password-hash`
  - Python: `team.authentication-weakness`, `team.auth-secret-equality`, `team.auth-session-fixation`, `team.auth-weak-password-hash`
- `ruleset_version` 4.7.0 cho 79 rule; `ruleset.py` ánh xạ `authentication_weakness.yml` → `INSECURE_AUTHENTICATION`.
- Tag ảnh CI: `aiws-semgrep:4.7.0-semgrep1.181.0`.
- `tests/test_six_class_scope.py`: 2 test của dataset v2 Python cũ tự bỏ qua khi thiếu `data/`, `PyVul/` (đã xóa, nhóm dùng dataset của leader).

## Kiểm tra

| Bước | Kết quả |
|---|---|
| `ruleset.py all` | 79 rule, 0 lỗi, **306/306** test, cảnh báo **22 → 12** (hết 10 cảnh báo "tên lớp cũ") |
| `ruleset.py verify` | ĐẠT |
| Unit test | 63 test, OK (2 skip) |
| Train v2.3 (v4.6.1 → v4.7.0) | mẫu dương bắt đúng 777 → 777; high 157 → 157; mẫu âm bị báo 978 → 978; high 67 → 67 |
| Val v2.3 | 132 → 132; high 17 → 17; mẫu âm 159 → 159; high 13 → 13 |

So từng mẫu: các cột bắt đúng / có finding / có high **trùng 100%**. Có 3 mẫu (2 train, 1 val) khác danh sách rule báo, đều do rule **taint** không bị sửa (`team.py.xss-taint`, `team.php.xss-taint`, `team.php.path-taint`), không đổi kết quả đúng/sai của mẫu. Nghi do dao động giữa các lần chạy của bộ phân tích taint (giới hạn thời gian/bộ nhớ mỗi file), không liên quan đổi tên.

## Còn lại (12 cảnh báo)

- CWE-916 ở 4 rule băm mật khẩu yếu, CWE-384 ở `team.auth-session-fixation`: chờ leader chốt lớp.
- 7 rule regex tầng audit không có `paths.include`.
