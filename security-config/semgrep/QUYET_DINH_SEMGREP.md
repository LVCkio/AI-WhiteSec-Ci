# Quyết định phần Semgrep (người phụ trách Semgrep)

Ba quyết định dưới đây là **quyết định cuối cùng** của người phụ trách Semgrep (xác nhận lại 2026-10-26, sau khi cân nhắc phương án GitHub Actions). Không đổi nếu chưa có quyết định mới.

| Ngày | Quyết định | Căn cứ | Ghi chú |
|---|---|---|---|
| 2026-10-26 | CI chạy trên **GitLab CI** (`.gitlab-ci.yml`) | `docs/semgrep_tool.md` mục 2.1 (P1, [Chốt]); đã so với GitHub Actions: kết quả quét như nhau, GitLab khớp tài liệu và sơ đồ đồ án | Repo GitHub `LVCkio/AI-WhiteSec-Ci` giữ để lưu mã; GitHub Actions cũ không dùng cho pipeline quét. Chặn merge bằng mã thoát của job gate (approval policy theo severity cần GitLab Ultimate). |
| 2026-10-26 | Runner dùng **Docker** | GitLab Runner: Docker executor cho môi trường sạch mỗi lần build; mẫu CI chính thức của Semgrep dùng image `semgrep/semgrep` | Ghim Semgrep **1.181.0** (tag image cố định hoặc image tự build với `semgrep==1.181.0`), không dùng `latest`. |
| 2026-10-26 | Finding tầng **audit chỉ ghi nhận, không chặn build** | Semgrep Policies: Block thường dành cho rule high-confidence/high-severity; số đo val v2.3: audit báo nhầm ~19% mẫu âm, high 1,5%; quét repo thật: 189 audit, 0 high | Tầng **high** được đưa vào gate. Quy tắc BLOCK/REVIEW cụ thể khi ghép với CodeBERT do phía gate (leader) chốt. |
| 2026-10-26 | GitLab **tự cài trong máy ảo** (GitLab CE self-managed), quản trị qua SSH; **không dùng GitLab.com** | GitLab.com bắt xác minh tài khoản (điện thoại/thẻ) trước khi chạy pipeline; máy ảo không giới hạn phút CI, nhóm tự kiểm soát | Vẫn là GitLab CI + runner Docker (giữ 2 quyết định trên). Thử nghiệm trên GitLab.com (project `fpt-edu-kltn-group/AI-WhiteSec-Ci`, runner trên Docker Desktop) dừng lại. |

Chưa chốt (chờ leader): đổi tên lớp Auth → `INSECURE_AUTHENTICATION` (v4.7.0); CWE-916/CWE-384; xử lý test trùng repo 72%; tách `.semgrepignore`; người duyệt 11 mẫu; máy chạy runner và nơi lưu model.

## Ruleset v4.8.0 (2026-11-14) — Semgrep là vệ tinh của CodeBERT

Trưởng nhóm duyệt phương án ngày 14/11/2026. Số đo đầy đủ: `Claude outputs/semgrep_v471_val_v26/` (DE_XUAT_CAT_TIA_v4.7.1.md, BAO_CAO_v4.8.0.md).

| Ngày | Quyết định | Căn cứ | Ghi chú |
|---|---|---|---|
| 2026-11-14 | Vai trò Semgrep: neo độ chính xác (tầng high), chỉ điểm dòng lỗi, đối chứng cho CodeBERT; không đua recall | CodeBERT V5 bắt 25,5% mẫu dương val v2.6, báo nhầm 10,0%; Semgrep v4.7.1 high macro-F1 0,120 | Thêm rule chỉ khi có ≥ 3 mẫu train và thêm được mẫu dương mà rule hiện có chưa bắt |
| 2026-11-14 | TC4 từ v4.8.0 tính **precision mẫu gồm cả mẫu âm** (mẫu rule báo đúng lớp / mọi mẫu rule báo) | Gate ci-2: `sast_only.high = BLOCK` — mỗi finding high đứng riêng đã chặn build | Mẫu âm v2.6 gồm bản sau vá và `hneg` (có thể chứa lỗi chưa gán nhãn) nên số này là cận dưới; báo kèm số "bỏ hneg" |
| 2026-11-14 | Tắt 8 rule audit (precision mẫu train < 0,25, ≥ 30 mẫu bị báo) | Train: mẫu âm bị báo 20,0% → 13,5%, recall 28,0% → 23,9%, macro-F1 0,299 → 0,293 | Rule chuyển sang `rules_disabled/` (metadata `disabled_v480`); test cũ lưu ở `tests_disabled/v4.8.0/` |
| 2026-11-14 | Hạ high → audit: `team.xss-unsafe-html`, `team.php.hardcoded-password-compare`, `team.path-request-taint` | Rà 142 finding high trên 76 mẫu âm (`high_neg_triage_v26.csv`): lỗi do pattern | `team.path-request-taint` là taint nên có `tier_exception` |
| 2026-11-14 | Siết `team.js.hardcoded-secret` (giữ high) | Train: báo nhầm 7 → 1 mẫu, không mất mẫu đúng (26/26); val giữ 3/3 | Bỏ qua giá trị có khoảng trắng (trừ khóa PEM) và snake_case chữ thường; cùng bộ lọc cho `jwt.sign/verify` |
| 2026-11-14 | **Không** thêm `team.js.cmdi-param`, `team.py.cmdi-wrapper` | JS: 27 mẫu dương train bắt đúng nhưng cả 27 đã bị rule OS hiện có bắt, thêm 11 mẫu âm; Python: 2 mẫu train (< 3) | Hai mẫu đúng mới trên val là mẫu đã xem khi thiết kế, không tính |

Chưa xong: duyệt 15 mẫu âm của `team.os-command-injection` (13) và `team.sql-injection` (2) trong `Claude outputs/semgrep_v471_val_v26/DOC_TAY_high_os_sql.md`. Nhận định sơ bộ (AI): 13/15 là rule báo nhầm (không thấy sanitizer ở dòng trên), 1 lỗi thật, 1 chưa rõ — không phải nhãn sai như giả thuyết ban đầu. Tầng high v4.8.0 đạt precision 0,74 train / 0,60 val; chỉ phương án hạ thêm 4 rule (A) đạt 0,84 train.

## Ruleset v4.8.1 (2026-11-14) — phương án A cho tầng high

Trưởng nhóm duyệt ngày 14/11/2026. Bản v4.8.0 lưu ở `archive/semgrep_v4.8.0_before_v481_2026-11-14.zip`.
Bundle sha256 `7087a64d08b40726aa40cd294ffa81cb9d40ce6a83878bb7a34ef01879c9486b` · 71 rule (23 high / 48 audit) · 285/285 test đạt · `verify` ĐẠT.

| Ngày | Quyết định | Căn cứ | Ghi chú |
|---|---|---|---|
| 2026-11-14 | Hạ high → audit 6 rule có ≥ 5 mẫu bị báo trên train và precision < 0,80: `team.os-command-injection` (0,52), `team.sql-injection` (0,60), `team.os-command-string-building` (0,40), `team.php.hardcoded-secret` (0,44), `team.py.xss-taint` (0,56), `team.js.xss-taint` (0,50) | Gate ci-2 BLOCK mọi finding high; đọc tay 15 mẫu âm của 2 rule đầu: 13 rule báo nhầm, 1 lỗi thật, 1 chưa rõ (`DOC_TAY_high_os_sql.md`) | Precision tầng high train 0,74 → 0,84; mẫu âm bị BLOCK (train) 41 → 16; recall tầng high 4,6% → 3,5%. Val: mẫu âm bị BLOCK 0,8% → 0,4% (n nhỏ, chỉ đối chiếu) |
| 2026-11-14 | Cách đọc tầng high | TC4 cần ≥ 5 mẫu bị báo | Trong 23 rule high còn lại, chỉ **3 rule credential** (`team.java.hardcoded-secret`, `team.js.hardcoded-secret`, `team.hardcoded-credentials`) đã kiểm chứng theo TC4; **20 rule còn lại chưa đủ dữ liệu** (< 5 mẫu bị báo trên train), không gọi là "đã kiểm chứng". Thực tế Semgrep tự BLOCK gần như chỉ với HARDCODED_CREDENTIALS; Injection/XSS đi vào REVIEW |

Còn lại: chạy tập test một lần bằng `50_eval_once.py` khi có `test_probs.npy` của CodeBERT V5; merge nhánh CI vào `develop`.

