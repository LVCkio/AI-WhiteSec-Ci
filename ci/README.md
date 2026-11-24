# Pipeline 1 (cha) và Pipeline 2 (con) – AI-WhiteSec-CI

Phiên bản 0.1.0 (27/10/2026). Model: **`V3`** (dataset v2.4, cửa sổ trượt; leader chốt dùng 31/10, thay `v24_pair_e5`). Quy trình đổi model: **`ci/MODEL_UPDATE.md`**. Ruleset Semgrep: v4.7.0. Tách hàm: **lizard** tạm thời cho buổi review (nhóm quyết định 29/10), sau review chuyển lại **tree-sitter** — đổi `AIWS_UNIT_BACKEND` trong `ci/pipeline2-worker.yml` (không cần build lại ảnh).

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
| `.gitlab-ci.yml` | Pipeline 1 (cha) của chính repo này: include `ci/pipeline1-orchestrator.yml` + job `dispatch-worker` |
| `ci/pipeline1-orchestrator.yml` | Job Pipeline 1 dùng chung (19/11/2026) |
| `ci/templates/target-project.gitlab-ci.yml` | Mẫu `.gitlab-ci.yml` cho **project khác** muốn được quét (mục 7) |
| `ci/pipeline2-worker.yml` | Pipeline 2 (con); include job Semgrep có sẵn `security-config/semgrep/ci/gitlab-ci-semgrep.yml` |
| `ci/aiws_ci/` | Mã P0–P5 (`p0_authorize`, `p1_scope`, `units`, `p3_codebert`, `p4_compare_gate`, `p5_persist`, `model_tool`) |
| `ci/gate-policy.json` | Chính sách Gate (có phiên bản; SHA-256 ghi vào báo cáo) |
| `ci/model-lock.json` | Model đang dùng: tên run + SHA-256 từng file đã duyệt |
| `ci/docker/Dockerfile.codebert` | Ảnh `aiws-codebert` (không chứa model) |
| `ci/servers/*.sh` | Cài runner Server 1, ảnh + kho model Server 3; `server3_rebuild_images.sh` build lại **cả hai** ảnh từ một commit |
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
Thứ tự (19/11/2026): (1) `sudo bash security-config/semgrep/ci/servers/server3_worker.sh <URL GitLab> ~/AI-WhiteSec-Ci` — Docker, GitLab Runner, ảnh `aiws-semgrep` (tag lấy từ `ruleset-manifest.json`), đăng ký runner **kèm** `volumes = ["/cache", "/srv/aiws/models:/models:ro"]`; khi tạo runner trên GitLab điền Tags `aiws-worker`. (2) lệnh `server3_pipeline2.sh` ở trên — ảnh `aiws-codebert` + model. Runner đăng ký trước 19/11 thì vẫn phải thêm `volumes` vào `config.toml` bằng tay (script (1) sẽ cảnh báo nếu thiếu).

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

**Model đọc hàm theo cửa sổ trượt (V3 trở đi).** `model-lock.json` có trường `inference`: `head512` (v24_pair_e5: 512 token đầu; không ghi = head512) hoặc `window` (V3: thân 510 token, stride 256, tối đa 8 cửa sổ, gộp LSE r=5). Với `window`, P3 và `ci/tools/explain_backfill.py` nạp **đúng** `scripts/infer_window.py` (+ `train_codebert_win.py`, `eval_utils.py`) đi kèm gói model — 3 file này được khóa SHA-256 trong lock và P0 kiểm trước khi chạy (mã: `ci/aiws_ci/scoring.py`). Gói V3 không có `MANIFEST.json` → `model_tool lock <thư mục V3> --sums <SHA256SUMS.txt>`.

- `ci/model-lock.json` = **V3** (val v2.4 macro-F1 0,503, báo nhầm 42,8%). Leader chốt 31/10: dùng luôn V3, đánh giá cả hàm ≤ và > 512 token.
- `ci/model-lock.v24_pair_e5.json`: model cũ (0,4865 / 30,9%) để quay lại. Chạy 1 lần với model cũ: Run pipeline với biến `AIWS_MODEL_LOCK = ci/model-lock.v24_pair_e5.json` (pipeline con nhận qua `forward: pipeline_variables`).
- V3 chậm hơn khoảng 2–2,5 lần trên CPU (trung bình ~2,4 cửa sổ mỗi hàm).

**Khi sửa mã `ci/aiws_ci/*.py`**: các job P0–P5 chạy mã đóng trong ảnh `aiws-codebert` (`/opt/aiws/ci`), không chạy mã trong commit. Sau khi merge/push, trên Server 3 chạy `git pull` rồi `docker build -f ci/docker/Dockerfile.codebert -t aiws-codebert:0.1.0 .` (dùng cache, ~1 phút). Nếu quên, `p0-authorize` dừng với thông báo `anh aiws-codebert chua ma CU (lech: ...)`. Đổi `ci/gate-policy.json` hay `ci/model-lock.json` thì không cần build lại (đọc từ commit).

## 7. Còn chờ nhóm quyết

- Ngưỡng/quy tắc Gate chính thức (Phase 6.2): hiện CodeBERT một mình chỉ đưa vào REVIEW.
- Dataset huấn luyện vẫn tách hàm theo CVEfixes `method_change` + lizard; pipeline đã chuyển sang tree-sitter. Trên `flask_vuln_app` ranh giới hàm tree-sitter và lizard trùng 36/36; nên đo thêm trên Java/JS/PHP (`AIWS_UNIT_BACKEND=lizard` để so).
- `executor` ghi vào `pipeline_runs` là `gitlab_ci`; nếu bảng có ràng buộc giá trị, đặt `AIWS_DB_EXECUTOR`.


## 7. Bổ sung 19/11/2026

**Quét project khác.** Chép `ci/templates/target-project.gitlab-ci.yml` vào gốc project cần quét, đặt tên `.gitlab-ci.yml`. Pipeline 1, Pipeline 2 và job Semgrep đều lấy từ AI-WhiteSec-Ci (`include: project`), không chép file nào khác. Lý do không dùng được `trigger: include: local`: GitLab tìm file đó trong project **gốc** đang chạy pipeline (gitlab-org/gitlab#219342). Điều kiện: người kích hoạt có quyền đọc AI-WhiteSec-Ci; hai runner `aiws-orchestrator` / `aiws-worker` được bật cho project đó (Settings → CI/CD → Runners → Enable); biến `AIWS_DB_DSN` đặt ở project hoặc group; ref `main` của AI-WhiteSec-Ci đã có bản `ci/` và `security-config/semgrep/` cần dùng.

**Semgrep chỉ quét file P1 chọn.** `aiws-semgrep` chờ `p1-scope` và truyền `--only-files aiws-out/p1-scope.json` (biến `AIWS_SEMGREP_TARGETS`: `p1` mặc định, `all` = quét hết như cũ). Chế độ diff → chỉ quét file bị sửa. Thời gian cả pipeline không tăng vì P3 cũng chờ P1 và P4 chờ cả hai.

**Kiểm ảnh đúng phiên bản.** `aiws-semgrep` gọi `scan_repo.py --expect-ruleset $AIWS_RULESET_VERSION --expect-manifest <repo>/security-config/semgrep/ruleset-manifest.json`: ảnh mang ruleset khác biến, hoặc (khi quét chính AI-WhiteSec-Ci) khác sha256 manifest trong commit → mã 2, Gate báo INCOMPLETE thay vì âm thầm quét bằng rule cũ. `p0-authorize` so thêm `scan_repo.py` và `.semgrepignore` trong ảnh `aiws-codebert` với commit.

**Kiểm hai ảnh nhìn cùng tập file.** `scan_repo.py` ghi `run.scope_signature` (sha256 của đuôi file, `.semgrepignore`, ngưỡng dòng); P1 ghi cùng giá trị vào `p1-scope.json`; P4 so hai giá trị và so danh sách file, lệch → mục `warnings` trong `report.json` và `summary.md` (không đổi quyết định Gate). Sửa: `sudo bash ci/servers/server3_rebuild_images.sh ~/AI-WhiteSec-Ci`.

**Độ phủ ngôn ngữ.** P1 và Semgrep đếm file mã nguồn ngôn ngữ chưa hỗ trợ (`.ts/.tsx`, `.vue`, `.go`, `.kt`…; `files_unsupported_language`). Có → cảnh báo trong báo cáo: PASS không bao gồm các file đó. Chưa thêm TypeScript vào phạm vi quét: cần rule/test TS, dữ liệu đo và quyết định của leader (model chưa train trên TS).

**Xuống dòng.** `.gitattributes` giữ LF cho rule, `semgrep.yml`, manifest, `ci/`, `*.sh`. Trước đó Git for Windows (`core.autocrlf=true`) đổi sang CRLF → `ruleset.py verify` KHÔNG ĐẠT và build ảnh từ bản Windows (`run_ci_semgrep_local.bat`) thất bại.

## 8. Mức tool Semgrep 4 bậc (22/11/2026, câu 6 nhóm thống nhất)

Mỗi finding Semgrep có thêm `tool_level` (Critical / High / Medium / Low), ghép từ `metadata.severity` của rule (mức nghiêm trọng của **loại** lỗ hổng, gắn khi viết rule; thiếu thì lấy `default_severity` của lớp trong `docs/taxonomy.yml`) × `metadata.confidence`:

| `metadata.severity` | `confidence: high` | `confidence: audit` |
|---|---|---|
| critical | Critical | Medium |
| high | High | Medium |
| medium | Medium | Low |

Rule audit không bao giờ lên Critical/High. Không dùng `severity` cấp rule (ERROR/WARNING/INFO) vì ở bộ rule nhóm nó chỉ là bản sao của `confidence` (ERROR = high, WARNING = audit) nên ghép chỉ ra 2 mức. Bộ v4.8.1 (71 rule): Critical 7 · High 13 · Medium 39 · Low 12. **Không sửa rule, không đổi SHA bộ rule.**

Ở đâu: `semgrep-results.json` (`findings[].tool_level`, `summary.by_tool_level`), `report.json` (`summary.semgrep_levels`, `tools[semgrep].normalized_findings[].level`, `gate.units[].sast_level`, `gate.units[].cells[].semgrep_tool_level`), `summary.md` (dòng "Mức tool Semgrep"). Bảng nằm ở `ci/aiws_ci/common.py` (`tool_level`) và bản chép trong `scan_repo.py` (ảnh `aiws-semgrep` không có `aiws_ci`); `tests/test_tool_level_20261122.py` kiểm hai bản khớp nhau.

**Gate 5×3 (nhóm chốt 22/11)**: trục Semgrep của Gate là mức tool (`gate-policy.json`: `semgrep_levels.field = tool_level`, `policy_version` `5x3-2026-11-22+ov1`):

| Mức tool \ CodeBERT | Cao (≥ α10) | Thấp (α20…α10) | Không |
|---|---|---|---|
| Critical | BLOCK | **BLOCK** | REVIEW |
| High | BLOCK | REVIEW | REVIEW |
| Medium | REVIEW | INFO | INFO |
| Low | REVIEW | INFO | INFO |
| Không | REVIEW | INFO | PASS |

Khác bảng 3×3 (20/11): Critical × Thấp = BLOCK (trước REVIEW); 3 rule confidence high của lớp mức medium (XSS) nằm ở hàng Medium (trước hàng High). Bảng cũ giữ ở `matrix_3x3_truoc_2211`; quay lại = đặt `semgrep_levels` về `truoc_2211` và `matrix` về bảng cũ (P4 đọc trục theo cấu hình). `team_overrides` (HARDCODED, thư mục tests) giữ nguyên. Finding thiếu `impact_severity` → mức mặc định của lớp trong `docs/taxonomy.yml`. **Worker trên server đọc `gate_3x3.json` riêng → phải đồng bộ bảng này lên server để hai nơi cùng kết luận.** Mức của Model (CodeBERT) 4 bậc theo "bảng điểm" chưa có định nghĩa, làm sau khi nhóm chốt.

Sửa `scan_repo.py` và `ci/aiws_ci/*.py` → trên Server 3 chạy `sudo bash ci/servers/server3_rebuild_images.sh ~/AI-WhiteSec-Ci` sau khi merge (nếu quên, `p0-authorize` dừng vì ảnh `aiws-codebert` chứa mã cũ).

## 9. Gate 5×5 (23/11/2026, nhóm chốt – dùng chung với worker Server 3)

`gate-policy.json` `policy_version` `5x5-2026-11-23`: `matrix`, `model_levels`, `team_overrides` chép **nguyên** từ `security-config/gate/gate_5x5.json` của worker (`source_gate_5x5.sha256` = `e7beee1a…`), nên lượt CI và lượt tải lên dashboard cho cùng một kết luận (đã đối chiếu `decide_5x5` với `security_gate_5x5` của worker trên 30.000 kịch bản ngẫu nhiên: 0 lệch).

- **Trục Semgrep**: giữ như 5×3 (mục 8), hàng `None` = không có finding.
- **Trục CodeBERT 5 mức**: mức CVSS của lớp (`model_levels.severity_by_class`: SQLi, Hardcoded = Critical; OS command, Path traversal, Auth = High; XSS = Medium). Điểm ≥ `thresholds.json` (α10) = *strong* → giữ mức; α20 ≤ điểm < α10 (`thresholds_weak`) = *weak* → hạ 1 bậc; còn lại → `None`.

| Semgrep \ CodeBERT | Critical | High | Medium | Low | None |
|---|---|---|---|---|---|
| Critical | BLOCK | BLOCK | BLOCK | REVIEW | REVIEW |
| High | BLOCK | BLOCK | REVIEW | REVIEW | REVIEW |
| Medium | BLOCK | REVIEW | REVIEW | INFO | INFO |
| Low | REVIEW | REVIEW | INFO | INFO | INFO |
| None | REVIEW | REVIEW | INFO | INFO | PASS |

`team_overrides`: Hardcoded *strong* cần p ≥ 0,95 (thấp hơn → *weak*); Hardcoded chỉ model báo (`None/Critical`, `None/High`) → INFO; đơn vị trong `tests/` tối đa INFO. Một luồng lỗi → tối đa REVIEW; cả hai lỗi → FAIL.

Mỗi ô trong `gate.units[].cells[]` có thêm `tool`, `model`, `model_base`, `model_confidence`, `tool_rule` (giữ `semgrep` / `codebert` cho dashboard cũ); `gate.gate_kind` = `5x5`, `gate.model_severity`. P4 chọn bảng theo cấu hình: có `model_levels` → `decide_5x5`, không có → `decide_3x3` (5×3 / 3×3 cũ). Bảng 5×3 giữ ở `truoc_2311`; quay lại 5×3 = khôi phục `gate-policy.json` của commit `70263d6`. **Đổi bảng ở một nơi phải đổi cả `gate_5x5.json` trên Server 3.** Test: `tests/test_gate_5x5_20261123.py`.

Chỉ sửa `ci/aiws_ci/p4_compare_gate.py` → sau khi merge vẫn phải build lại ảnh trên Server 3 (`server3_rebuild_images.sh`), vì `p0-authorize` so mã trong ảnh với commit.
