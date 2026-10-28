#!/usr/bin/env bash
# Server 1 (Dashboard & Orchestrator) - runner SHELL cho PIPELINE 1 (CHA), tag aiws-orchestrator.
# Pipeline cha chi dieu phoi (bash + curl + python3 thu vien chuan), khong chay Docker, khong can ma nguon
# -> nhe, hop voi Server 1 dang chay GitLab CE (5 GB RAM).
#
# Dung:  sudo bash ci/servers/server1_orchestrator_runner.sh <URL GitLab, vd http://192.168.12.200:8929>
#   Token runner: GitLab -> project ai-whitesec-ci -> Settings -> CI/CD -> Runners -> New project runner,
#   Tags = aiws-orchestrator, KHONG tick "Run untagged jobs" -> Create -> giu token glrt-... (khong gui ai).
set -euo pipefail
GITLAB_URL="${1:-}"
if [[ -z "$GITLAB_URL" ]]; then echo "Dung: sudo bash $0 <URL GitLab>"; exit 1; fi
if [[ $EUID -ne 0 ]]; then echo "Can chay bang sudo"; exit 1; fi

echo "== Goi can cho job cha =="
apt-get update && apt-get install -y curl python3 ca-certificates

echo "== GitLab Runner (kho chinh thuc packages.gitlab.com) =="
if ! command -v gitlab-runner >/dev/null; then
  curl -fsSL https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh | bash
  apt-get install -y gitlab-runner
fi
gitlab-runner --version | head -2

if grep -q 'name = "aiws-server1-orchestrator"' /etc/gitlab-runner/config.toml 2>/dev/null; then
  echo "Runner aiws-server1-orchestrator da dang ky - bo qua"
else
  read -r -s -p "Dan runner token (glrt-...), Enter: " RUNNER_TOKEN; echo
  [[ -n "$RUNNER_TOKEN" ]] || { echo "Chua nhap token"; exit 1; }
  gitlab-runner register --non-interactive --url "$GITLAB_URL" --token "$RUNNER_TOKEN" \
    --name "aiws-server1-orchestrator" --executor shell
  unset RUNNER_TOKEN
fi
# Moi lan chi mot job cha tren Server 1 (tranh tranh RAM voi GitLab)
sed -i 's/^concurrent = .*/concurrent = 1/' /etc/gitlab-runner/config.toml || true
systemctl enable --now gitlab-runner
gitlab-runner verify || true
echo "Kiem tra: curl -fsS http://127.0.0.1/api/health (job p5-report doc ket qua qua API nay)"
curl -fsS -m 5 http://127.0.0.1/api/health && echo || echo "(chua goi duoc WhiteSec API - p5-report se bao 'khong doc duoc')"
