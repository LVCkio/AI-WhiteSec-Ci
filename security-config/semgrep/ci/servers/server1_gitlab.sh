#!/usr/bin/env bash
# server1 - cai GitLab CE (Linux package chinh thuc) cho AI-WhiteSec-CI.
# Dung:  sudo bash server1_gitlab.sh <IP server1> [cong] [--small]
#   cong    : cong web cua GitLab (mac dinh 8929) - cong 80 de cho Dashboard (nginx he thong).
#   --small : che do it RAM (puma 1 tien trinh, sidekiq 5, tat Prometheus/exporter) cho may ao ~5 GB RAM.
#   Ubuntu qua moi (kho GitLab chua co ban) -> tu dung goi cho Ubuntu 24.04 (noble).
# Sau khi cai: mo http://<IP>:<cong> tu may that, dang nhap root bang mat khau trong
#   /etc/gitlab/initial_root_password (file tu xoa sau 24 gio - doi mat khau ngay).
set -euo pipefail

IP="${1:-}"; PORT="8929"; SMALL=""
for a in "${@:2}"; do
  if [[ "$a" == "--small" ]]; then SMALL="--small"; elif [[ "$a" =~ ^[0-9]+$ ]]; then PORT="$a"; fi
done
if [[ -z "$IP" ]]; then echo "Dung: sudo bash $0 <IP server1> [cong=8929] [--small]"; exit 1; fi
if [[ $EUID -ne 0 ]]; then echo "Can chay bang sudo"; exit 1; fi
URL="http://${IP}:${PORT}"
[[ "$PORT" == "80" ]] && URL="http://${IP}"

echo "== Kiem tra tai nguyen =="
MEM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
SWAP_GB=$(awk '/SwapTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
DISK_GB=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
echo "RAM ${MEM_GB} GB, swap ${SWAP_GB} GB, CPU $(nproc), dia trong ${DISK_GB} GB"
if (( DISK_GB < 6 )); then echo "DUNG: can >= 6 GB dia trong (goi GitLab ~3 GB)"; exit 1; fi
if (( MEM_GB < 7 )) && [[ -z "$SMALL" ]]; then echo "RAM < 8 GB -> tu bat --small"; SMALL="--small"; fi
if (( SWAP_GB < 1 )); then echo "CANH BAO: chua co swap, GitLab de bi het RAM"; fi
if ss -tln | grep -q ":${PORT} "; then echo "DUNG: cong ${PORT} dang bi chuong trinh khac dung"; ss -tlnp | grep ":${PORT} "; exit 1; fi

echo "== Goi phu thuoc =="
apt-get update
apt-get install -y curl openssh-server ca-certificates tzdata perl

echo "== Kho goi GitLab CE (packages.gitlab.com) =="
. /etc/os-release
if ! curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | bash; then
  echo "Kho GitLab chua ho tro Ubuntu ${VERSION_ID} (${VERSION_CODENAME}) -> dung goi cho noble (24.04)"
  curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | os=ubuntu dist=noble bash
fi

echo "== Cai GitLab CE, external_url = ${URL} =="
EXTERNAL_URL="${URL}" apt-get install -y gitlab-ce

if [[ "$SMALL" == "--small" ]] && ! grep -q 'AI-WhiteSec-CI: may ao it RAM' /etc/gitlab/gitlab.rb; then
  echo "== Cau hinh tiet kiem bo nho =="
  cat >> /etc/gitlab/gitlab.rb <<'RB'

# --- AI-WhiteSec-CI: may ao it RAM (docs.gitlab.com/omnibus/settings/memory_constrained_envs) ---
puma['worker_processes'] = 0
sidekiq['concurrency'] = 5
prometheus_monitoring['enable'] = false
gitlab_rails['env'] = { 'MALLOC_CONF' => 'dirty_decay_ms:1000,muzzy_decay_ms:1000' }
gitaly['env'] = { 'MALLOC_CONF' => 'dirty_decay_ms:1000,muzzy_decay_ms:1000', 'GITALY_COMMAND_SPAWN_MAX_PARALLEL' => '2' }
RB
  gitlab-ctl reconfigure
fi

if command -v ufw >/dev/null && ufw status | grep -q active; then
  ufw allow OpenSSH; ufw allow "${PORT}/tcp"
fi

echo
echo "== Xong =="
gitlab-ctl status | head -20 || true
echo "Mo ${URL} tren may that. Tai khoan: root"
echo "Mat khau tam: sudo cat /etc/gitlab/initial_root_password   (doi ngay sau lan dang nhap dau)"
