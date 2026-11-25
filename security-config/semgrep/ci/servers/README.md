# Cài đặt server cho AI-WhiteSec-CI (GitLab CE tự cài)

Kiến trúc: **server1** = GitLab CE (cùng Dashboard/Orchestrator); **server3** = Security Worker (GitLab Runner Docker + ảnh `aiws-semgrep`, sau này job CodeBERT); **server2** = Data (PostgreSQL, model, log) – không cần cho phần Semgrep.

## 1. server1 – GitLab CE

```bash
scp security-config/semgrep/ci/servers/server1_gitlab.sh server1:~
ssh server1
sudo bash server1_gitlab.sh <IP server1>            # thêm --small nếu máy ảo chỉ 8 GB RAM
sudo cat /etc/gitlab/initial_root_password           # mật khẩu root tạm, đổi ngay
```

Mở `http://<IP server1>` trên máy thật → đăng nhập `root` → đổi mật khẩu → tạo user cho từng thành viên → tạo group/project `AI-WhiteSec-Ci` → đẩy mã:

```bash
git remote add selfhosted http://<IP server1>/<group>/AI-WhiteSec-Ci.git
git push selfhosted --all
```

Yêu cầu tối thiểu theo GitLab: 8 GB RAM (khuyến nghị 16 GB), 40 GB đĩa SSD.

## 2. server3 – Runner + ảnh Semgrep

1. Trên GitLab: project → **Settings → CI/CD → Runners → New project runner** → tick *Run untagged jobs* → Create → giữ token `glrt-…` (không gửi ai).
2. Trên server3:

```bash
ssh server3
git clone http://<IP server1>/<group>/AI-WhiteSec-Ci.git
sudo bash AI-WhiteSec-Ci/security-config/semgrep/ci/servers/server3_worker.sh http://<IP server1> ~/AI-WhiteSec-Ci
```

Script: cài Docker + GitLab Runner từ kho chính thức → build ảnh `aiws-semgrep:4.7.0-semgrep1.181.0` (chỉ build được khi `verify` đạt) → quét thử → hỏi token (ẩn) → đăng ký runner `aiws-server3` với `pull_policy = if-not-present` (dùng ảnh có sẵn, không cần registry).

3. Trên GitLab: runner `aiws-server3` phải **Online**. Push bất kỳ nhánh nào → pipeline tự chạy job `aiws-semgrep`.

## Khi đổi bộ rule

Trên server3: `git pull` rồi chạy lại script (bỏ qua bước đăng ký nếu đã có) để build ảnh mới; tăng `AIWS_RULESET_VERSION`/`AIWS_SEMGREP_IMAGE` trong `gitlab-ci-semgrep.yml` cho khớp tag.
