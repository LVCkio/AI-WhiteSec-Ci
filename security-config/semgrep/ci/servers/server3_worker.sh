#!/usr/bin/env bash
# server3 - Security Worker: Docker + GitLab Runner (Docker executor) + anh aiws-semgrep.
# Dung:  sudo bash server3_worker.sh <URL GitLab, vd http://192.168.150.10> <thu muc ma nguon AI-WhiteSec-Ci>
#   Thu muc ma nguon phai co docs/taxonomy.yml va security-config/semgrep/ (clone tu GitLab hoac chep bang scp).
#   Token runner (glrt-...) lay tren GitLab: project -> Settings -> CI/CD -> Runners -> New project runner
#   (tick "Run untagged jobs"). Script hoi token o dang AN, khong ghi ra man hinh hay log.
set -euo pipefail

GITLAB_URL="${1:-}"
SRC="${2:-}"
TAG="aiws-semgrep:4.7.0-semgrep1.181.0"
if [[ -z "$GITLAB_URL" || -z "$SRC" ]]; then echo "Dung: sudo bash $0 <URL GitLab> <thu muc AI-WhiteSec-Ci>"; exit 1; fi
if [[ $EUID -ne 0 ]]; then echo "Can chay bang sudo"; exit 1; fi
if [[ ! -f "$SRC/docs/taxonomy.yml" || ! -f "$SRC/security-config/semgrep/ci/Dockerfile" ]]; then
  echo "Thieu $SRC/docs/taxonomy.yml hoac security-config/semgrep/ci/Dockerfile"; exit 1; fi

echo "== Kiem tra ket noi toi GitLab =="
curl -fsS -o /dev/null -w "HTTP %{http_code}\n" "$GITLAB_URL/users/sign_in" || { echo "Khong goi duoc $GITLAB_URL"; exit 1; }

echo "== Docker Engine (kho chinh thuc download.docker.com) =="
if ! command -v docker >/dev/null; then
  apt-get update
  apt-get install -y ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
fi
systemctl enable --now docker
docker version --format 'Docker {{.Server.Version}}'

echo "== GitLab Runner (kho chinh thuc packages.gitlab.com) =="
if ! command -v gitlab-runner >/dev/null; then
  curl -fsSL https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh | bash
  apt-get install -y gitlab-runner
fi
gitlab-runner --version | head -2

echo "== Build anh $TAG (chi build duoc khi ruleset.py verify DAT) =="
( cd "$SRC" && DOCKER_BUILDKIT=1 docker build -f security-config/semgrep/ci/Dockerfile -t "$TAG" . )

echo "== Thu anh: quet chinh ma nguon =="
OUT=$(mktemp -d); chmod 777 "$OUT"   # user scanner (uid 10001) trong anh can ghi ket qua
docker run --rm -v "$SRC:/src:ro" -v "$OUT:/out" "$TAG" \
  --repo /src --repo-name AI-WhiteSec-Ci --out /out/semgrep-results.json --scope-out /out/scope.json
rm -rf "$OUT"

echo "== Dang ky runner =="
if grep -q "url = \"$GITLAB_URL" /etc/gitlab-runner/config.toml 2>/dev/null; then
  echo "Runner da dang ky voi $GITLAB_URL - bo qua"
else
  read -r -s -p "Dan runner token (glrt-...), Enter: " RUNNER_TOKEN; echo
  [[ -n "$RUNNER_TOKEN" ]] || { echo "Chua nhap token"; exit 1; }
  gitlab-runner register --non-interactive \
    --url "$GITLAB_URL" --token "$RUNNER_TOKEN" \
    --name "aiws-server3" \
    --executor docker --docker-image alpine:3.20 \
    --docker-pull-policy if-not-present
  unset RUNNER_TOKEN
fi
systemctl enable --now gitlab-runner
gitlab-runner verify || true

echo
echo "== Xong =="
docker image ls "$TAG"
echo "Kiem tra tren GitLab: Settings -> CI/CD -> Runners: runner aiws-server3 phai Online."
