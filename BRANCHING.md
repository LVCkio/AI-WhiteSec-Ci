# Quy ước nhánh – AI-WhiteSec-CI (FCA26IA18)

## Các nhánh

| Nhánh | Vai trò | Ai được ghi |
|---|---|---|
| `main` | Bản ổn định: bản nộp, bản demo, bộ rule đã phát hành. | Chỉ merge qua Pull Request từ `develop` khi phát hành. Không commit thẳng. |
| `develop` | Nhánh tích hợp: các việc đã xong và đã kiểm tra. | Chỉ merge qua Pull Request từ nhánh việc. Không commit thẳng. |
| `semgrep/<phase>-<mo-ta>` | Việc của phần Semgrep, mỗi phase (R0–R6) một nhánh. | Người viết rule. Tách từ `develop`, xong thì mở PR về `develop`. |
| `codebert/<mo-ta>` | Việc của phần CodeBERT. | Thành viên phụ trách CodeBERT. |
| `dashboard/<mo-ta>` | Việc của dashboard. | Thành viên phụ trách dashboard. |
| `ci/<mo-ta>` | GitLab CI / pipeline. | Thành viên phụ trách CI. |
| `hotfix/<mo-ta>` | Sửa gấp trên bản đã phát hành. | Tách từ `main`, merge về cả `main` và `develop`. |

Tên nhánh: chữ thường, không dấu, nối bằng `-`.

## Nhánh Semgrep theo kế hoạch R0–R6 (`docs/semgrep_tool.md` mục 8.2)

| Nhánh | Nội dung |
|---|---|
| `semgrep/r0-nhap-ruleset-v4.3.1` | Đưa mã nguồn ruleset v4.3.1 (rule, test, công cụ, tài liệu, script đo) vào repo. |
| `semgrep/r1-do-nen-v22` | Đo nền trên train/val v2.2 (bảng 24 ô, tỉ lệ parse, FN train). |
| `semgrep/r2-no-v42` | Đóng việc dở của v4.2. |
| `semgrep/r3-registry` | Rà Semgrep Registry, bundle đối chứng đã ghim. |
| `semgrep/r4-rule-moi` | Rule mới cho các ô thiếu. |
| `semgrep/r5-dong-bang` | Đóng băng bundle, đánh giá cuối. |
| `semgrep/r6-hoc-lai` | Danh sách học lại (đã người duyệt). |

Chỉ tạo nhánh khi bắt đầu phase đó.

## Tag phát hành

- Bộ rule: `semgrep-v<ruleset_version>`, ví dụ `semgrep-v4.3.1`. Chỉ gắn sau khi `ruleset.py all` và `ruleset.py verify` đạt.
- Model / gate: `codebert-<tên>` (do phía CodeBERT quyết định).

## Không đưa vào repo

- Dataset (train/val/test, `*.jsonl`, `*.csv` của dữ liệu), file model, checkpoint, `.venv`.
- Báo cáo có khóa hoặc tên repo của **tập test v2.2** (ví dụ `r1_overlap_*`), và file chứa code mẫu (`*_tuning_subset.csv`). Các file này giữ ở máy và gửi trực tiếp cho leader.
- File zip đóng gói.

## Quy trình một việc

1. `git switch develop && git pull`
2. `git switch -c semgrep/<phase>-<mo-ta>`
3. Sửa, chạy `ruleset.py all` + `ruleset.py verify`, commit.
4. `git push -u origin semgrep/<phase>-<mo-ta>`, mở Pull Request về `develop`.
5. Khi phát hành: PR `develop` → `main`, gắn tag.
