# Semgrep trong GitLab CI (P2)

Theo `QUYET_DINH_SEMGREP.md`: **GitLab CI**, runner **Docker**, Semgrep ghim **1.181.0**, finding tầng **audit chỉ ghi nhận, không chặn build**.

## File

| File | Vai trò |
|---|---|
| `Dockerfile` | Ảnh `aiws-semgrep`: Python 3.11 + Semgrep 1.181.0 + bộ rule đã đóng gói + `scan_repo.py`. Ảnh **chỉ build được khi `ruleset.py verify` đạt**. |
| `Dockerfile.dockerignore` | Chỉ đưa vào ảnh `docs/taxonomy.yml`, bundle, manifest, `.semgrepignore`, `rules/`, `ruleset.py`, `scan_repo.py` (không đưa dataset, model, báo cáo). |
| `gitlab-ci-semgrep.yml` | Hai job: `aiws-semgrep-image` (build và đẩy ảnh lên GitLab Container Registry) và `aiws-semgrep` (quét, xuất artifact). |

## Dùng trong `.gitlab-ci.yml` ở gốc repo

```yaml
stages: [build-image, sast, compare, gate]
include:
  - local: security-config/semgrep/ci/gitlab-ci-semgrep.yml
```

Job CodeBERT (`sast` hoặc stage riêng), ghép P4 (`compare`) và `gate` do phía CodeBERT/gate thêm sau; chúng đọc artifact `semgrep-results.json` và `scope.json` của job `aiws-semgrep`.

## Hành vi job `aiws-semgrep`

1. Kiểm tra cấu hình (Semgrep 1.181.0, `ruleset.py verify`, `taxonomy.yml`). Sai → **mã 2, job đỏ** = "Kiểm tra cấu hình và môi trường SAST" thất bại, báo người quản lý pipeline (P1).
2. Chọn phạm vi theo `.semgrepignore` trong ảnh + loại file dòng trung bình > 300 ký tự → `scope.json`.
3. Quét → `semgrep-results.json` (định dạng `docs/semgrep_tool.md` mục 2.3).
4. **Có finding vẫn mã 0, job xanh.** Chặn build là việc của job gate: chỉ finding `confidence: high` được đưa vào gate; `audit` chỉ ghi nhận.
5. Semgrep lỗi khi quét → mã 3, job đỏ.

Chạy khi: merge request, nhánh mặc định, hoặc chạy tay (Run pipeline).

## Yêu cầu runner

- GitLab Runner **Docker executor**.
- Job `aiws-semgrep-image` dùng `docker:27-dind` → runner cần `privileged = true`. Nếu runner không cho privileged, build ảnh trên máy rồi `docker push` tay lên registry với đúng tag `$AIWS_SEMGREP_IMAGE`.
- Tag ảnh = `aiws-semgrep:<ruleset_version>-semgrep<semgrep_version>` (hiện `4.6.1-semgrep1.181.0`). Đổi bộ rule → tăng `AIWS_RULESET_VERSION` trong `gitlab-ci-semgrep.yml`.

## Chạy thử trên máy (Docker Desktop)

`main\run_ci_semgrep_local.bat`: build ảnh rồi quét repo `AI-WhiteSec-Ci` trong container; kết quả ở `security-config/semgrep/reports/ci_local_<ngày>/`.

## Còn mở

- Máy chạy runner (leader): cần Docker và quyền privileged nếu build ảnh trong CI.
- `.semgrepignore` đang trộn mục chung và mục riêng đồ án (`data/`, `models/`…); quét repo ứng dụng khác có thể loại nhầm. Chờ thống nhất với phía CodeBERT.
- Quét repo ứng dụng khác: include template này qua `include: project:` và dùng chung ảnh trong registry.
