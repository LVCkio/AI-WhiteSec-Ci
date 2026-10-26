# Quyết định phần Semgrep (người phụ trách Semgrep)

Ba quyết định dưới đây là **quyết định cuối cùng** của người phụ trách Semgrep (xác nhận lại 2026-10-26, sau khi cân nhắc phương án GitHub Actions). Không đổi nếu chưa có quyết định mới.

| Ngày | Quyết định | Căn cứ | Ghi chú |
|---|---|---|---|
| 2026-10-26 | CI chạy trên **GitLab CI** (`.gitlab-ci.yml`) | `docs/semgrep_tool.md` mục 2.1 (P1, [Chốt]); đã so với GitHub Actions: kết quả quét như nhau, GitLab khớp tài liệu và sơ đồ đồ án | Repo GitHub `LVCkio/AI-WhiteSec-Ci` giữ để lưu mã; GitHub Actions cũ không dùng cho pipeline quét. Chặn merge bằng mã thoát của job gate (approval policy theo severity cần GitLab Ultimate). |
| 2026-10-26 | Runner dùng **Docker** | GitLab Runner: Docker executor cho môi trường sạch mỗi lần build; mẫu CI chính thức của Semgrep dùng image `semgrep/semgrep` | Ghim Semgrep **1.181.0** (tag image cố định hoặc image tự build với `semgrep==1.181.0`), không dùng `latest`. |
| 2026-10-26 | Finding tầng **audit chỉ ghi nhận, không chặn build** | Semgrep Policies: Block thường dành cho rule high-confidence/high-severity; số đo val v2.3: audit báo nhầm ~19% mẫu âm, high 1,5%; quét repo thật: 189 audit, 0 high | Tầng **high** được đưa vào gate. Quy tắc BLOCK/REVIEW cụ thể khi ghép với CodeBERT do phía gate (leader) chốt. |
| 2026-10-26 | GitLab **tự cài trong máy ảo** (GitLab CE self-managed), quản trị qua SSH; **không dùng GitLab.com** | GitLab.com bắt xác minh tài khoản (điện thoại/thẻ) trước khi chạy pipeline; máy ảo không giới hạn phút CI, nhóm tự kiểm soát | Vẫn là GitLab CI + runner Docker (giữ 2 quyết định trên). Thử nghiệm trên GitLab.com (project `fpt-edu-kltn-group/AI-WhiteSec-Ci`, runner trên Docker Desktop) dừng lại. |

Chưa chốt (chờ leader): đổi tên lớp Auth → `INSECURE_AUTHENTICATION` (v4.7.0); CWE-916/CWE-384; xử lý test trùng repo 72%; tách `.semgrepignore`; người duyệt 11 mẫu; máy chạy runner và nơi lưu model.
