#!/usr/bin/env bash
# Cai 1 LAN tren Server 3 (user pipeline): giai thich CodeBERT TU DONG cho moi lan tai ma nguon len dashboard.
#   bash ci/tools/cai_tu_dong_giai_thich.sh          (hoi mat khau whitesec_ci + sudo de tao systemd timer)
# Go bo: sudo systemctl disable --now aiws-explain.timer && sudo rm /etc/systemd/system/aiws-explain.{service,timer}
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
ENVF="$HOME/.config/aiws/explain.env"
mkdir -p "$(dirname "$ENVF")" && chmod 700 "$(dirname "$ENVF")"
if [[ ! -s "$ENVF" ]]; then
  read -rsp "Mat khau PostgreSQL cua whitesec_ci (luu vao $ENVF, chi $USER doc duoc): " PW; echo
  umask 077; printf 'PGPASSWORD=%s\n' "$PW" > "$ENVF"; unset PW
fi
chmod 600 "$ENVF"
echo "== chay thu 1 lan =="
bash "$REPO/ci/tools/tu_dong_giai_thich.sh"
echo "== tao systemd timer (moi 2 phut) =="
sudo tee /etc/systemd/system/aiws-explain.service >/dev/null <<UNIT
[Unit]
Description=AI-WhiteSec: giai thich CodeBERT cho luot tai len moi
After=docker.service network-online.target
[Service]
Type=oneshot
User=$USER
Environment=HOME=$HOME
ExecStart=/usr/bin/bash $REPO/ci/tools/tu_dong_giai_thich.sh
Nice=10
UNIT
sudo tee /etc/systemd/system/aiws-explain.timer >/dev/null <<UNIT
[Unit]
Description=AI-WhiteSec: kiem tra luot tai len moi moi 2 phut
[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now aiws-explain.timer
systemctl list-timers aiws-explain.timer --no-pager
echo "Xong. Xem nhat ky: journalctl -u aiws-explain -n 30 --no-pager"
