#!/usr/bin/env bash
# Server 3: chay bu giai thich CodeBERT cho 1 version tai len.  Dung: bash ci/tools/giai_thich_version.sh <version id>
# Can: anh aiws-codebert:0.1.0, kho model /srv/aiws/models, bang public.codebert_explanations (codebert_explanations.sql).
set -euo pipefail
VID="${1:?Dung: bash $0 <version id>  (vd Terarium v5 -> id trong /api/versions)}"
REPO=$(cd "$(dirname "$0")/../.." && pwd)
CA="${AIWS_DB_CA:-$HOME/.config/whitesec/db-ca.pem}"
[[ -r "$CA" ]] || { echo "Khong doc duoc chung chi CA $CA (dat AIWS_DB_CA=<duong dan>)"; exit 1; }
read -rsp "Mat khau PostgreSQL cua whitesec_ci: " PGPASSWORD; echo; export PGPASSWORD
docker run --rm --user "$(id -u):$(id -g)" -e PGPASSWORD -e HOME=/tmp -e USER=aiws -e LOGNAME=aiws -e TORCHINDUCTOR_CACHE_DIR=/tmp/torchinductor \
  -e AIWS_DB_DSN="host=192.168.12.202 port=5432 dbname=whitesec user=whitesec_ci sslmode=verify-full sslrootcert=/ca.pem" \
  -v "$CA:/ca.pem:ro" -v /srv/aiws/models:/models:ro -v "$REPO/ci/tools:/tools:ro" \
  -v "${AIWS_WORKER_MODEL_STORE:-$HOME/whitesec-work/models/store}:/worker_models:ro" \
  aiws-codebert:0.1.0 python /tools/explain_backfill.py --version "$VID" "${@:2}"
