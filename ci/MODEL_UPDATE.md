# Cập nhật model CodeBERT (train mới → pipeline)

Leader chốt (31/10/2026): **model train mới là dùng luôn**, kể cả khi có thay đổi; model đánh giá cả hàm **≤ 512** và **> 512 token** (cửa sổ trượt). Tài liệu này ghi: thư mục nằm ở đâu, khi có train mới thì đổi file nào, và từng bước lấy file nào để chạy.

Model đang dùng: **V3** (dataset v2.4) — `ci/model-lock.json`. Model cũ để quay lại: `ci/model-lock.v24_pair_e5.json`.

---

## 1. Cấu trúc thư mục

### 1.1 Gói model leader giao (`handoff_model_<TÊN>.zip`)

```
handoff_model_V3.zip
├── SHA256SUMS.txt                ← SHA-256 từng file (đường dẫn có tiền tố model_V3/)
├── README_HANDOFF.md
└── model_V3/
    ├── checkpoint/
    │   ├── config.json               multi-label 6 nhãn (problem_type = multi_label_classification)
    │   ├── model.safetensors         trọng số (~500 MB)
    │   ├── tokenizer.json
    │   └── tokenizer_config.json
    ├── thresholds.json           6 ngưỡng của RIÊNG model này
    ├── run_config.json           cấu hình train + CÁCH ĐỌC HÀM: stride, max_windows, pool, lse_r, groups, version, data
    ├── metrics_val.json          số đo trên val (dashboard hiện ở "Đánh giá mô hình")
    ├── val_probs.npy             điểm val lúc train → kiểm tra gói sau khi cài
    ├── report_val.md, history.json, README_HANDOFF.md
    └── scripts/
        ├── infer_window.py       suy luận cửa sổ trượt + gộp — pipeline NẠP ĐÚNG file này, không viết lại
        ├── train_codebert_win.py hàm chia cửa sổ (window_starts) + gộp (pool_np) mà infer_window.py import
        └── eval_utils.py         GROUPS (thứ tự 6 cột logits)
```

**Điều kiện để KHÔNG phải sửa code pipeline** khi có model mới (chỉ đổi lock):
- giữ đúng tên/vị trí các file trên;
- `run_config.json` có `version` (tên model), `data` (đường dẫn kết thúc bằng tên dataset, vd `...\v2.4`), `groups`, và — nếu đọc theo cửa sổ — `stride`, `max_windows`, `pool`, `lse_r`;
- `scripts/infer_window.py` giữ hàm `load(model_dir)`, `score(codes, tok, model, dev, win, chunk)`, `window_lines(...)`, biến `BODY`, `GROUPS`;
- 6 nhóm, cùng thứ tự: PATH_TRAVERSAL, XSS, OS_COMMAND_INJECTION, SQL_INJECTION, INSECURE_AUTHENTICATION (= AUTHENTICATION_WEAKNESS), HARDCODED_CREDENTIALS.

Đổi một trong các điều trên (thêm nhóm, đổi tên hàm, cách gộp mới chưa có trong `infer_window.py`...) → báo Cường sửa `ci/aiws_ci/scoring.py`.

### 1.2 Trên các server

| Máy | Đường dẫn | Nội dung | Ai dùng |
|---|---|---|---|
| Laptop leader | `D:\DATASET\runs\<TÊN>\` | Kết quả train gốc | Leader |
| Server 2 (192.168.12.202, `dataset`) | `~/whitesec-data/datasets/v2.4/` | train/val/test `.jsonl` | Leader |
| Server 3 (192.168.12.201, `pipeline`) | `~/handoff_model_<TÊN>.zip` (+ `.sha256.txt`) | Gói leader gửi lên | — |
| Server 3 | `~/whitesec-work/models/store/<TÊN>/` | Kho model của **worker** (luồng tải ZIP lên dashboard) | Worker (Trường) |
| Server 3 | `~/whitesec-work/models/active.json` | Model worker đang dùng (V3 từ 31/10) | Worker (Trường) |
| Server 2 | `~/whitesec-data/models/<TÊN>/`, `models/LATEST` | Kho model phát hành cho worker (`whitesec-model`) | Worker kéo về |
| Server 3 | `~/whitesec-infra/pipeline/codebert/aiws_infer.py` | Code chấm của worker (ảnh `aiws-codebert:cpu`) | Worker (Trường) |
| Server 3 | **`/srv/aiws/models/<TÊN>/`** | Kho model của **pipeline CI** (runner mount vào job thành `/models`, chỉ đọc) | P0, P3, timer tô tím |
| Server 3 | `~/val.jsonl` | val v2.4 (SHA-256 `06033fd8…`) để kiểm tra gói | Cường |
| Server 3 | `~/AI-WhiteSec-Ci/` | Clone repo → build ảnh `aiws-codebert:0.1.0` | Cường |

### 1.3 Trong repo (`AI-WhiteSec-Ci`)

| File | Vai trò | Đổi khi có model mới? |
|---|---|---|
| `ci/model-lock.json` | **Model pipeline dùng**: tên, cách suy luận (`inference`), SHA-256 từng file | **CÓ** (tạo bằng `model_tool lock`) |
| `ci/model-lock.<tên cũ>.json` | Lock model cũ để quay lại | Nên giữ 1 bản |
| `ci/aiws_ci/scoring.py` | Chấm điểm theo `inference`: `head512` hoặc `window` (nạp `scripts/infer_window.py` của gói) | Chỉ khi đổi cách suy luận |
| `ci/aiws_ci/p0_authorize.py` | Kiểm SHA-256 mọi file trong lock (cả 3 script) trước khi quét | Không |
| `ci/aiws_ci/p3_codebert.py` | Chấm hàm + giải thích (occlusion) | Không |
| `ci/aiws_ci/model_tool.py` | `lock` / `install` / `verify` | Không |
| `ci/tools/explain_backfill.py` + timer `aiws-explain` | Tô tím CodeBERT cho lượt tải ZIP lên (dùng `/srv/aiws/models/<TÊN>`) | Không |

---

## 2. Khi có train mới — các bước

Ví dụ tên model mới là `V4`. Thay `V4` bằng tên thật (`run_config.json` → `version`).

### Bước 1 — Leader giao gói lên Server 3
Chép `handoff_model_V4.zip` + `.sha256.txt` vào `~` của Server 3, rồi:
```bash
cd ~ && sha256sum handoff_model_V4.zip && cat handoff_model_V4.zip.sha256.txt     # hai dòng phải giống nhau
mkdir -p ~/tmp_V4 && unzip -o handoff_model_V4.zip -d ~/tmp_V4
ls ~/tmp_V4          # thấy model_V4/ và SHA256SUMS.txt
```
(Kho của worker `~/whitesec-work/models/store/V4/` do worker/Trường cài như với V3.)

### Bước 2 — Kiểm tra gói khớp lúc train (bắt buộc)
```bash
cd ~/tmp_V4/model_V4 && sed 's#model_V4/##' ../SHA256SUMS.txt | sha256sum -c -        # tất cả OK
docker run --rm --user $(id -u):$(id -g) -e HOME=/tmp -v ~/tmp_V4/model_V4:/m:ro -v ~/val.jsonl:/d/val.jsonl:ro \
  --entrypoint python3 aiws-codebert:0.1.0 /m/scripts/infer_window.py --model-dir /m --verify-val /d/val.jsonl --n 20
```
Phải in `KHỚP`. (Lỗi `Read-only file system` cuối cùng là bình thường.) Không khớp → dừng, báo leader.
Nếu model train trên dataset mới (vd v2.5) thì chép `val.jsonl` của dataset đó từ Server 2 sang, dùng thay `~/val.jsonl`.

### Bước 3 — Tạo lock (trên laptop, trong thư mục repo)
Lấy các file nhỏ của gói về (không lấy `model.safetensors`):
```bash
# Server 3
cd ~/tmp_V4/model_V4 && tar czf ~/V4_meta.tgz scripts run_config.json thresholds.json metrics_val.json -C ~/tmp_V4 SHA256SUMS.txt
```
```powershell
# Laptop (PowerShell) — tên file đích ghi rõ, không để "\" cuối
scp -o ConnectTimeout=30 pipeline@192.168.12.201:V4_meta.tgz "D:\Đồ án FCA26IA18\_dashboard_work\V4_meta.tgz"
```
Giải nén vào `_dashboard_work\V4_meta\`, rồi trong thư mục `AI-WhiteSec-Ci\ci`:
```bash
git mv model-lock.json model-lock.V3.json                     # giữ model đang dùng để quay lại
python -m aiws_ci.model_tool lock "../../_dashboard_work/V4_meta" --sums "../../_dashboard_work/V4_meta/SHA256SUMS.txt" --out model-lock.json
```
In ra `model V4 (dataset v2.x, val macro-F1 ..., suy luan window, 10 file)`. Lệnh tự kiểm SHA-256 các file có sẵn.

### Bước 4 — Cài model vào kho của CI (Server 3)
```bash
cd ~/AI-WhiteSec-Ci && git pull        # có lock mới (sau khi push bước 3)
docker run --rm --user 0 -v ~/tmp_V4/model_V4:/pkg:ro -v /srv/aiws/models:/store -v "$PWD/ci:/w:ro" \
  --entrypoint python aiws-codebert:0.1.0 -m aiws_ci.model_tool install /pkg --lock /w/model-lock.json --store /store
docker run --rm --user 0 -e HOME=/tmp -v /srv/aiws/models:/store -v ~/val.jsonl:/val.jsonl:ro \
  --entrypoint python aiws-codebert:0.1.0 -m aiws_ci.model_tool verify /store/V4 --val /val.jsonl --n 20 --save
```
`install` từ chối nếu file nào lệch SHA-256. `verify` phải in `"pass": true`; `--save` ghi `infra_verify.json` để dashboard hiện bằng chứng.

### Bước 5 — Commit + chạy pipeline
Commit `ci/model-lock.json` (+ lock cũ), push, **Run pipeline MỚI** trên GitLab. Không cần build lại ảnh khi chỉ đổi model.
`p0-authorize` in `model V4: ok; N file da kiem SHA-256`; `p3-codebert` in số hàm, số bị cắt (window), thời gian.

### Bước 6 — Worker (luồng tải ZIP lên dashboard)
Worker **không** đọc `store/` trực tiếp: mỗi job nó đọc `models/LATEST` trên **Server 2**, rsync `models/<TÊN>/` về `~/whitesec-work/models/store/<TÊN>/`, kiểm `SHA256SUMS` + `MODEL.json`; model MỚI → tự chấm lại **toàn bộ val** của dataset (container `aiws-codebert:cpu`, 2 CPU) và chỉ ghi `active.json` khi macro-F1 lệch ≤ 0,01 so với `MODEL.json`; không đạt → giữ model cũ.

Phát hành trên **Server 2** (công cụ `whitesec-model` của Trường):
```bash
# gói đã giải nén ở ~/whitesec-data/incoming/handoff_model_V4 (SHA256SUMS.txt + model_V4/)
whitesec-model publish V4 ~/whitesec-data/incoming/handoff_model_V4 --dataset v2.4     # chép, khóa chỉ đọc, MODEL.json, LATEST -> V4
whitesec-model use v24_pair_e5                                                          # quay lại model cũ
```
- `publish` từ chối nếu `models/<TÊN>` đã tồn tại → thư mục chép tay dở thì đổi tên (vd `mv models/V3 models/.V3-chep-tay-<ngày>`) rồi publish lại.
- Script `nap-handoff.sh` của Server 2 dừng ở bước 5 nếu máy thiếu numpy/torch (31/10: `No module named 'numpy'`) — model không lỗi; dùng `whitesec-model publish` như trên.
- Lượt upload ĐẦU TIÊN sau khi publish có bước "Kiểm tra model mới trên tập validation": V3 mất **1.301 s** (~22 phút) cho 1.225 hàm. Không hủy job giữa chừng.
- Kết quả: Server 1 `python3 ~/whitesec-infra/server/model_check_report.py` → `TAI TAO DUOC: True`. V3 (31/10): hạ tầng 0,5036 / lúc train 0,503.

Worker đọc theo cửa sổ nhờ bản vá `ci/servers/worker/patch_worker_v3.py` cho `~/whitesec-infra/pipeline/codebert/aiws_infer.py` (đã áp 31/10, sao lưu `aiws_infer.py.bak-20261031-160650`): model có `run_config.max_windows` → nạp `scripts/infer_window.py` của gói; model khác vẫn 512 token đầu. Khi Trường cài lại hạ tầng (ghi đè `aiws_infer.py`) phải vá lại rồi build: `python3 patch_worker_v3.py aiws_infer.py && docker build -q -t aiws-codebert:cpu .` trong thư mục đó.

**Tô tím** (timer `aiws-explain`) dùng `/srv/aiws/models/<tên model của lượt quét>` → làm **Bước 4 trước** khi publish cho worker, nếu không các lượt tải lên bị ghi "skipped".

---

## 3. Pipeline lấy file và chạy thế nào

```
GitLab (Server 1) ── Run pipeline ──► runner Server 3 (ảnh aiws-codebert:0.1.0, mount /srv/aiws/models → /models:ro)
  P0 p0-authorize : đọc ci/model-lock.json của COMMIT (hoặc $AIWS_MODEL_LOCK)
                    → /models/<name>/ : kiểm SHA-256 từng file trong "files" (checkpoint, thresholds, run_config,
                      metrics_val, scripts/*.py) → ghi p0-authorize.json (model, inference, thresholds, val_metrics,
                      infra_verify)
  P1 p1-scope     : tách hàm (lizard/tree-sitter) → p1-units.jsonl
  P3 p3-codebert  : scoring.Scorer theo "inference":
                      head512 → tokenizer cắt 512 token đầu
                      window  → nạp /models/<name>/scripts/infer_window.py → load() đọc run_config (stride, K, pool)
                                + thresholds → score() chấm từng cửa sổ, gộp LSE → sigmoid
                    → gắn cờ nếu điểm ≥ ngưỡng; occlusion 6 khối cho hàm gắn cờ → codebert-results.json
  P4 p4-compare-gate : so với Semgrep → Gate (policy ci/gate-policy.json)
  P5 p5-persist   : ghi PostgreSQL (Server 2) → dashboard
```

Lượt tải ZIP lên dashboard: worker quét bằng model trong `active.json`; timer `aiws-explain` (2 phút/lần, Server 3) chạy `explain_backfill.py` → nạp `/srv/aiws/models/<tên>` bằng cùng `scoring.Scorer` → ghi `public.codebert_explanations`.

## 4. Quay lại model cũ
- Một lần: Run pipeline với biến `AIWS_MODEL_LOCK = ci/model-lock.v24_pair_e5.json`.
- Hẳn: đổi tên lock cũ thành `ci/model-lock.json`, commit. Model cũ vẫn nằm trong `/srv/aiws/models/`.

## 5. Khi nào phải build lại ảnh `aiws-codebert`
Chỉ khi sửa `ci/aiws_ci/*.py`: trên Server 3 `cd ~/AI-WhiteSec-Ci && git pull && docker build -f ci/docker/Dockerfile.codebert -t aiws-codebert:0.1.0 .`, rồi Run pipeline MỚI (không Retry). Đổi model/lock thì **không** cần.
