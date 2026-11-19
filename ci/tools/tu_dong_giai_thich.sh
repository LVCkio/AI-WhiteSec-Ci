#!/usr/bin/env bash
# Chay 1 luot TU DONG (systemd timer goi moi 2 phut): giai thich CodeBERT cho cac luot tai len moi.
# Mat khau DB doc tu ~/.config/aiws/explain.env (chi chu so huu doc duoc) - tao bang cai_tu_dong_giai_thich.sh.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
ENVF="${AIWS_EXPLAIN_ENV:-$HOME/.config/aiws/explain.env}"
CA="${AIWS_DB_CA:-$HOME/.config/whitesec/db-ca.pem}"
exec 9>/tmp/aiws-explain.lock
flock -n 9 || { echo "dang co luot giai thich khac chay - bo qua"; exit 0; }
docker run --rm --user "$(id -u):$(id -g)" --env-file "$ENVF" -e HOME=/tmp -e USER=aiws -e LOGNAME=aiws \
  -e TORCHINDUCTOR_CACHE_DIR=/tmp/torchinductor -e AIWS_TORCH_THREADS="${AIWS_TORCH_THREADS:-2}" \
  -e AIWS_DB_DSN="host=192.168.12.202 port=5432 dbname=whitesec user=whitesec_ci sslmode=verify-full sslrootcert=/ca.pem" \
  -v "$CA:/ca.pem:ro" -v /srv/aiws/models:/models:ro -v "$REPO/ci/tools:/tools:ro" \
  -v "${AIWS_WORKER_MODEL_STORE:-$HOME/whitesec-work/models/store}:/worker_models:ro" \
  aiws-codebert:0.1.0 python /tools/explain_backfill.py --pending --limit "${AIWS_EXPLAIN_LIMIT:-3}"
