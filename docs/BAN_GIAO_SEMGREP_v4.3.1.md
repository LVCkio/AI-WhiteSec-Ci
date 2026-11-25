# Bàn giao ruleset Semgrep – AI-WhiteSec-CI (FCA26IA18)

Cập nhật: 2026-10-25. Dùng để mở phiên làm việc mới mà không mất ngữ cảnh.

## 1. Bối cảnh hệ thống
- Semgrep CE (ruleset của nhóm) và CodeBERT (C03 + verifier p_vulnerable ≥ 0,594) chạy song song → Compare → Security Gate (BLOCK / REVIEW / PASS).
- Quyết định nhóm: dùng **CodeBERT + Semgrep**, **bỏ Bandit** (không đưa vào gate, không làm đối chứng). TF-IDF/CodeT5 chỉ giữ làm baseline.
- 6 lớp: SQL_INJECTION, XSS, OS_COMMAND_INJECTION, PATH_TRAVERSAL, INSECURE_AUTHENTICATION (tên cũ AUTHENTICATION_WEAKNESS), HARDCODED_CREDENTIALS. 4 ngôn ngữ: Python, Java, JavaScript, PHP.

## 2. Trạng thái ruleset
- Phiên bản **v4.3.1**: 81 rule (5 rule tắt nằm ở `rules_disabled/`), 270 test (128 positive / 142 negative). Semgrep ghim **1.181.0**.
- v4.3.0 đã chạy đủ trên Windows (check 0 lỗi, 270/270 test, verify đạt). **v4.3.1 chưa chạy bằng Semgrep**: cần chạy `main\run_ruleset_v43.bat` để sinh bundle/manifest/test mới, rồi đóng gói lại zip cho leader.
- Thay đổi v4.3.1: thêm `metadata.tier_exception` cho `team.path-from-parameter` (Python, rule_version 1.1.0) và `team.php.path-taint` (PHP, 1.2.0); `ruleset.py check` không còn cảnh báo hai rule này (cảnh báo 32 → 30, 0 lỗi). Pattern không đổi.
- v4.3.0 so với v4.2.0: 30 rule đổi (rule_version +0.1.0, có `change_v43`), severity Semgrep suy từ confidence, `metadata.severity` suy từ lớp, `team.php.path-taint` hạ high → audit. Bản cũ lưu ở `security-config/semgrep/archive/` (v4.0.0 … v4.3.0).
- `docs/taxonomy.yml` v0.3.0: SQL [89]; XSS [79]; OS_CMD [78,77,88]; PATH [22,23,36]; AUTH [287,306,307] (CWE-916 xếp theo metadata, chờ chốt); CRED [798,259,321]. default_severity: critical/medium/critical/high/high/high.

## 3. Quy tắc cứng (từ `Semgrep/CLAUDE.md`, `docs/semgrep_tool.md`)
- Không dùng Bandit.
- Chỉnh rule chỉ bằng **train**, kiểm bằng **val**. Không đọc/quét tập test và 4 ứng dụng mục tiêu khi chỉnh rule. Không đọc kết quả CodeBERT trên test. Test chỉ quét **một lần** (J01 `--final`, R5).
- Sau mọi thay đổi rule: `ruleset.py all` rồi `ruleset.py verify`. Sửa rule → tăng `rule_version`; phát hành bộ mới → tăng `ruleset_version`. Rule tắt chuyển vào `rules_disabled/`, không xóa.
- Không sửa dữ liệu dataset, `models/gate_config.json`, file phía CodeBERT. Không dùng kết quả Semgrep làm nhãn.
- Làm trên nhánh git riêng; không commit vào nhánh chính, không push, không xóa file nếu chưa được đồng ý. Không chắc thì hỏi.
- Tầng: confidence high → ERROR, audit → WARNING (5.3); taint → high (5.2, ngoại lệ phải ghi `tier_exception`); regex chỉ khi có `paths.include`. TC4: high ≥ 0,80, audit ≥ 0,50, cần ≥ 5 hit (ít hơn: "chưa đủ dữ liệu", không tắt). TC5: không đổi ngưỡng.
- Số liệu chính thức đo trên **dataset v2.2** (leader giữ, không có trong workspace). Số hiện có (train/val v5, cặp a01) phải đo lại trên v2.2.

## 4. Công cụ và file (thư mục `main/`)
- `security-config/semgrep/tools/ruleset.py`: `check | test | build | all | verify`.
- `security-config/semgrep/{rules/, rules_disabled/, tests/, semgrep.yml, ruleset-manifest.json, reports/, archive/, TIEU_CHI_CHON_RULE.md}`; mục 7 (v4.3.0) và mục 8 (v4.3.1) của tiêu chí ghi các bổ sung.
- `reports/r2_kiem_tra_tieu_chi_v42_2026-10-25.{md,csv}`: kiểm 81 rule theo tiêu chí (32 rule đạt đủ, 12 đã sửa, 37 còn việc mở).
- `03_run_sast.py`: nhận cả INSECURE_AUTHENTICATION lẫn AUTHENTICATION_WEAKNESS (đọc `old_names` trong taxonomy), giữ nhãn gốc ở `cls_gt_original`. `21_rule_metrics.py`, `30_rule_pairs_diff.py` dùng lại, không sửa. Test: `tests/test_class_alias.py`.
- `33_overlap_keys.py` (R1): `extract` đã chạy → `reports/r1_tuning_keys_2026-10-25.{csv,json}` (17.493 khóa repo/commit/CVE/sha256 code, không chứa code). Leader chạy: `python 33_overlap_keys.py compare --test <test v2.2> --keys r1_tuning_keys_2026-10-25.csv` → báo cáo chồng lấn + `_tuning_subset.csv`.
- `run_ruleset_v43.bat` (chạy bằng `.venv`, log ở `reports/run_v43_log.txt`): all + verify + unit test (class_alias, six_class_scope, dashboard).
- Dữ liệu đã dùng để chỉnh v4.2: `v5_multilang` train/val, `a01_pairs_v51` train/val, `v5_1_e03`, `data/` (v3). 4 ứng dụng mục tiêu đã rà tay (TC6).
- Dashboard: `main/dashboard/` (màn "Cấu hình & Rule" hiển thị phiên bản, ngưỡng, rule). Do ruleset giờ là 4.3.x, lượt quét v4.2 cũ hiện là "cấu hình cũ". Repo đẩy GitHub: LVCkio/AI-WhiteSec-Ci (đã chuẩn bị local, người dùng tự push).
- Gói cho leader: `D:\Đồ án FCA26IA18\AIWS_semgrep_rules_v4.3.0_2026-10-25.zip` (cần làm lại cho v4.3.1).

## 5. Môi trường
- Cloud và VM không cài được Semgrep (pypi bị chặn). Semgrep 1.181.0, torch 2.14.1+cpu, transformers nằm trong `main\.venv` (Python 3.11.9) trên Windows của người dùng.
- VM thiết bị: Python 3.10, giới hạn 180 s mỗi lệnh. Cloud không push được GitHub.

## 6. Việc tiếp theo
1. Chạy `run_ruleset_v43.bat` (v4.3.1) → báo kết quả → đóng gói lại zip cho leader (kèm `33_overlap_keys.py`, file khóa R1, hướng dẫn `compare`).
2. Leader (có dataset v2.2): chạy `compare` R1; đo bảng 24 ô train/val v2.2, tỉ lệ parse, danh sách FN train.
3. Nếu có trùng test: đánh giá lại quyết định rule chỉ bằng train v2.2; R5 báo thêm kết quả khi bỏ repo trùng.
4. Khi có dataset/DATA_CARD mới (v2.3): tạo DATA_CARD mới, giữ nguyên card v2.2; chạy lại `21_rule_metrics.py`/`30_rule_pairs_diff.py`; thêm nguồn mới vào `TUNING_SOURCES` nếu dùng để chỉnh rule. Ý tưởng: ghi `dataset_version` + sha256 train/val vào manifest.

## 7. Quyết định còn mở (nhóm/leader)
- Đổi tên Auth thành INSECURE_AUTHENTICATION toàn hệ thống.
- CWE-916 (4 rule) và CWE-384 (`team.auth-session-fixation`) thuộc nhóm nào.
- 13 rule regex cần viết lại thành AST pattern; 14 rule audit rớt TC5-audit.
- `team.js.audit.fs-path-api` (val 2/9); 2 rule tắt có < 5 hit train.
- `team.php.xss-taint` cần rà tay (65 bản vá / 98 bản lỗi); ô PHP PATH_TRAVERSAL (6/120 train).
- Rà registry (R3); GitLab CI; schema dataset v2.2; `team.path-from-parameter` có lên high khi val v2.2 ≥ 5 hit và ≥ 0,80 không.
