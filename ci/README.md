# Pipeline 1 (cha) và Pipeline 2 (con) – AI-WhiteSec-CI

Phiên bản 0.1.0 (27/10/2026). Model: `v24_pair_e5` (dataset v2.4) của leader. Ruleset Semgrep: v4.7.0. Tách hàm: **lizard** tạm thời cho buổi review (nhóm quyết định 29/10), sau review chuyển lại **tree-sitter** — đổi `AIWS_UNIT_BACKEND` trong `ci/pipeline2-worker.yml` (không cần build lại ảnh).

## 1. Cấu trúc

```
commit / merge request / chạy tay / API
        │
 PIPELINE 1 (CHA) — .gitlab-ci.yml — Server 1, runner shell tag aiws-orchestrator
   p1-plan          xác định lần quét: nguồn kích hoạt, chế độ diff/full, commit gốc  → plan.env
   dispatch-worker  trigger PIPELINE 2, strategy: depend (Gate BLOCK / lỗi → pipeline cha thất bại → chặn merge)
   p5-report        đọc kết quả đã ghi ở PostgreSQL (Server 2) qua WhiteSec API, in tóm tắt (luôn chạy)
        │
 PIPELINE 2 (CON) — ci/pipeline2-worker.yml — Server 3, runner Docker tag aiws-worker
   p0-authorize     cấp quyền: HEAD đúng commit được giao + cây sạch; model đúng ci/model-lock.json (SHA-256 từng file)
   p1-scope         phạm vi file (dùng chung scan_repo.select_scope với Semgrep) + tách hàm tree-sitter → p1-units.jsonl
   aiws-semgrep  ║  p3-codebert      chạy song song, độc lập
   p4-compare-gate  gán finding vào hàm → agree / conflict / sast_only / codebert_only / pass → BLOCK / REVIEW / PASS
   p5-persist       ghi báo cáo schema 3 vào public.pipeline_runs (Server 2) → Dashboard hiển thị
```

| File | Vai trò |
|---|---|
| `.gitlab-ci.yml` | Pipeline 1 (cha) |
| `ci/pipeline2-worker.yml` | Pipeline 2 (con); include job Semgrep có sẵn `security-config/semgrep/ci/gitlab-ci-semgrep.yml` |
| `ci/aiws_ci/` | Mã P0–P5 (`p0_authorize`, `p1_scope`, `units`, `p3_codebert`, `p4_compare_gate`, `p5_persist`, `model_tool`) |
| `ci/gate-policy.json` | Chính sách Gate (có phiên bản; SHA-256 ghi vào báo cáo) |
| `ci/model-lock.json` | Model đang dùng: tên run + SHA-256 từng file đã duyệt |
| `ci/docker/Dockerfile.codebert` | Ảnh `aiws-codebert` (không chứa model) |
| `ci/servers/*.sh` | Cài runner Server 1, ảnh + kho model Server 3 |
| `tests/test_ci_pipeline.py` | Kiểm thử tách hàm và Gate |

## 2. Chế độ quét

| Kích hoạt | Chế độ | Đơn vị được xét |
|---|---|---|
| push | `diff` so với `CI_COMMIT_BEFORE_SHA` | hàm chứa dòng bị thêm/sửa; finding Semgrep trong các hàm đó hoặc trên dòng bị sửa |
| merge request | `diff` so với `CI_MERGE_REQUEST_DIFF_BASE_SHA` | như trên |
| chạy tay, API/Dashboard, nhánh mới | `full` | mọi hàm trong phạm vi |

Ép chế độ: biến `AIWS_SCAN_MODE_DEFAULT=full` khi chạy pipeline.

## 3. CodeBERT trong pipeline (khớp INFERENCE.md của gói model)

- Đầu vào: code **nguyên văn** của đơn vị, tokenizer của checkpoint, `truncation=True, max_length=512` (giữ 512 token đầu). Không gắn tag ngôn ngữ, không bỏ comment.
- Đầu ra: sigmoid từng cột theo thứ tự `PATH_TRAVERSAL, XSS, OS_COMMAND_INJECTION, SQL_INJECTION, AUTHENTICATION_WEAKNESS, HARDCODED_CREDENTIALS` (không đọc `id2label` vì checkpoint ghi `LABEL_0…5`); gắn nhóm khi `p ≥ thresholds.json`.
- Đơn vị `module_snippet` (dòng gán credential ngoài hàm ±5 dòng) chỉ xét `HARDCODED_CREDENTIALS`.
- Hàm < 2 dòng (`AIWS_MIN_FUNC_LINES`) vẫn dùng để gán finding Semgrep nhưng không đưa vào CodeBERT.

## 4. Security Gate – chính sách tạm `ci-2`

| Trạng thái | Quyết định |
|---|---|
| agree – Semgrep tầng high + CodeBERT cùng lớp | BLOCK |
| agree – Semgrep tầng audit + CodeBERT cùng lớp | REVIEW (audit không tự chặn build – `taxonomy.yml`) |
| sast_only – Semgrep tầng high | BLOCK |
| sast_only – Semgrep tầng audit | REVIEW |
| codebert_only | REVIEW (ngưỡng hiện là ngưỡng tối đa F1, chưa phải ngưỡng Gate) |
| conflict (cả hai báo, khác lớp) | REVIEW |
| CodeBERT lỗi → `degraded_sast_only` | high BLOCK / audit REVIEW; pipeline FAILED vì `require_model: true` |
| Semgrep lỗi → `degraded_codebert_only` | REVIEW; báo cáo `incomplete` |

Mã thoát `p4-compare-gate`: 0 PASS/REVIEW · 1 BLOCK · 2 thiếu model · 3 cả hai luồng lỗi. Quy tắc chính thức chờ nhóm chốt ở Phase 6.2 — sửa `ci/gate-policy.json` qua merge request.

Artifact: `aiws-out/report.json` (schema 3), `gate.json`, `summary.md`, `ai-whitesec.sarif`, và code quality report (hiện trong widget merge request).

## 5. Cài đặt (một lần)

**Server 1 – runner cho pipeline cha**
```bash
sudo bash ci/servers/server1_orchestrator_runner.sh http://192.168.12.200:8929
```
Tạo runner trên GitLab: Tags `aiws-orchestrator`, không tick "Run untagged jobs".

**Server 3 – ảnh + kho model + runner**
```bash
sudo bash ci/servers/server3_pipeline2.sh ~/AI-WhiteSec-Ci ~/model_v24_pair_e5 ~/val.jsonl
```
Sau đó sửa `/etc/gitlab-runner/config.toml` của runner `aiws-server3`: `volumes = ["/cache", "/srv/aiws/models:/models:ro"]`, restart runner, và thêm tag `aiws-worker` trên GitLab. Ảnh `aiws-semgrep:4.7.0-semgrep1.181.0` dùng lại như cũ.

**Biến CI/CD (Settings → CI/CD → Variables)** – chỉ cần cho P5 ghi PostgreSQL:

| Biến | Kiểu | Ví dụ |
|---|---|---|
| `AIWS_DB_DSN` | Variable, Masked, Protected | `host=192.168.12.202 port=5432 dbname=whitesec user=whitesec_ci sslmode=verify-full` |
| `AIWS_DB_CA` | File | chứng chỉ CA của PostgreSQL Server 2 |

Tài khoản `whitesec_ci` chỉ cần `SELECT, INSERT` trên `public.projects` và `SELECT, INSERT` trên `public.pipeline_runs`. Không đặt `AIWS_DB_DSN` → pipeline vẫn chạy, báo cáo chỉ nằm trong artifact.

## 6. Khi leader giao checkpoint mới

1. Máy dev: `python -m aiws_ci.model_tool lock <thư mục gói> --out ci/model-lock.json` (đọc `MANIFEST.json` của gói), mở merge request.
2. Server 3: `sudo bash ci/servers/server3_pipeline2.sh <repo> <gói mới> <val.jsonl>` – cài vào `/srv/aiws/models/<tên run>`, kiểm SHA-256, chấm lại 20 mẫu val so với `val_probs.npy`.
3. Merge → pipeline sau dùng model mới; model cũ vẫn nằm trong kho để quay lại (đổi lock về bản cũ).

Không cần build lại ảnh `aiws-codebert` khi chỉ đổi model.

**Model đọc hàm theo cửa sổ trượt (V3 trở đi).** `model-lock.json` có trường `inference`: `head512` (mặc định, v24_pair_e5: 512 token đầu) hoặc `window` (V3: thân 510 token, stride 256, tối đa 8 cửa sổ, gộp LSE r=5). Với `window`, P3 và `ci/tools/explain_backfill.py` nạp **đúng** `scripts/infer_window.py` (+ `train_codebert_win.py`, `eval_utils.py`) đi kèm gói model — 3 file này được khóa SHA-256 trong lock và P0 kiểm trước khi chạy (mã: `ci/aiws_ci/scoring.py`). Gói V3 không có `MANIFEST.json` → `model_tool lock <thư mục V3> --sums <SHA256SUMS.txt>`.

- `ci/model-lock.V3.json`: lock của V3 (val v2.4 macro-F1 0,503, báo nhầm 42,8%; v24_pair_e5: 0,4865 / 30,9%). **Chưa phải mặc định** — chờ leader chốt.
- Chạy thử V3 không đổi mặc định: Run pipeline với biến `AIWS_MODEL_LOCK = ci/model-lock.V3.json` (pipeline con nhận qua `forward: pipeline_variables`).
- Chuyển hẳn sang V3: chép `ci/model-lock.V3.json` đè `ci/model-lock.json` qua merge request. Chậm hơn khoảng 2–2,5 lần trên CPU.

**Khi sửa mã `ci/aiws_ci/*.py`**: các job P0–P5 chạy mã đóng trong ảnh `aiws-codebert` (`/opt/aiws/ci`), không chạy mã trong commit. Sau khi merge/push, trên Server 3 chạy `git pull` rồi `docker build -f ci/docker/Dockerfile.codebert -t aiws-codebert:0.1.0 .` (dùng cache, ~1 phút). Nếu quên, `p0-authorize` dừng với thông báo `anh aiws-codebert chua ma CU (lech: ...)`. Đổi `ci/gate-policy.json` hay `ci/model-lock.json` thì không cần build lại (đọc từ commit).

## 7. Còn chờ nhóm quyết

- Ngưỡng/quy tắc Gate chính thức (Phase 6.2): hiện CodeBERT một mình chỉ đưa vào REVIEW.
- Dataset huấn luyện vẫn tách hàm theo CVEfixes `method_change` + lizard; pipeline đã chuyển sang tree-sitter. Trên `flask_vuln_app` ranh giới hàm tree-sitter và lizard trùng 36/36; nên đo thêm trên Java/JS/PHP (`AIWS_UNIT_BACKEND=lizard` để so).
- `executor` ghi vào `pipeline_runs` là `gitlab_ci`; nếu bảng có ràng buộc giá trị, đặt `AIWS_DB_EXECUTOR`.
