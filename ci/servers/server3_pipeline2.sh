#!/usr/bin/env bash
# Server 3 (Security Worker) - chuan bi cho PIPELINE 2 (CON):
#   1. build anh aiws-codebert (P0 cap quyen, P1 tree-sitter, P3 CodeBERT CPU, P4 Gate, P5 ghi DB)
#   2. cai goi model cua leader vao kho /srv/aiws/models/<ten run> (kiem SHA-256 theo ci/model-lock.json)
#   3. (tuy chon) cham lai N mau val, so voi val_probs.npy cua leader
#   4. in huong dan sua runner: tag aiws-worker + mount kho model vao /models (chi doc)
#
# Dung:  sudo bash ci/servers/server3_pipeline2.sh <thu muc repo AI-WhiteSec-Ci> <thu muc goi model> [val.jsonl]
#   vd:  sudo bash ci/servers/server3_pipeline2.sh ~/AI-WhiteSec-Ci ~/model_v24_pair_e5 ~/v2.3/val.jsonl
set -euo pipefail

SRC="${1:-}"; PKG="${2:-}"; VAL="${3:-}"
IMG="aiws-codebert:0.1.0"
STORE="/srv/aiws/models"
if [[ -z "$SRC" || -z "$PKG" ]]; then echo "Dung: sudo bash $0 <repo AI-WhiteSec-Ci> <goi model> [val.jsonl]"; exit 1; fi
if [[ $EUID -ne 0 ]]; then echo "Can chay bang sudo"; exit 1; fi
SRC=$(realpath "$SRC"); PKG=$(realpath "$PKG")
for f in ci/docker/Dockerfile.codebert ci/model-lock.json ci/aiws_ci/model_tool.py; do
  [[ -f "$SRC/$f" ]] || { echo "Thieu $SRC/$f"; exit 1; }
done
[[ -f "$PKG/MANIFEST.json" && -f "$PKG/checkpoint/model.safetensors" ]] || { echo "$PKG khong phai goi model (thieu MANIFEST.json / checkpoint)"; exit 1; }
NAME=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['name'])" "$SRC/ci/model-lock.json")

echo "== 1. Build anh $IMG =="
( cd "$SRC" && DOCKER_BUILDKIT=1 docker build -f ci/docker/Dockerfile.codebert -t "$IMG" . )

echo "== 2. Cai model $NAME vao $STORE (kiem SHA-256 theo ci/model-lock.json) =="
mkdir -p "$STORE"
docker run --rm --user 0 -v "$SRC/ci/model-lock.json:/lock.json:ro" -v "$PKG:/pkg:ro" -v "$STORE:/store" "$IMG" \
  python -m aiws_ci.model_tool install /pkg --lock /lock.json --store /store ${FORCE:+--force}
chmod -R a+rX "$STORE"

if [[ -n "$VAL" ]]; then
  echo "== 3. Cham lai 20 mau val tren CPU, so voi val_probs.npy cua leader (sai so < 1e-3) =="
  docker run --rm -v "$STORE:/models:ro" -v "$(realpath "$VAL"):/val.jsonl:ro" "$IMG" \
    python -m aiws_ci.model_tool verify "/models/$NAME" --val /val.jsonl --n 20
fi

echo "== 4. Thu P0 cap quyen voi kho model =="
docker run --rm -v "$STORE:/models:ro" -v "$SRC:/src:ro" -e AIWS_EXPECTED_SHA= "$IMG" \
  python -c "from pathlib import Path; from aiws_ci.p0_authorize import check_model; import json; \
r=check_model(Path('/src'), Path('/models')); print(json.dumps({k:r.get(k) for k in ('status','name','files_checked','error')}, ensure_ascii=False))"

cat <<EOF

== 5. Sua runner aiws-server3 (lam MOT lan) ==
  a) /etc/gitlab-runner/config.toml, trong [runners.docker] cua runner aiws-server3, them dong:
        volumes = ["/cache", "$STORE:/models:ro"]
     roi: sudo gitlab-runner restart
  b) GitLab -> Settings -> CI/CD -> Runners -> aiws-server3 -> Edit -> Tags: aiws-worker
     (giu "Run untagged jobs" neu job aiws-semgrep cu con chay tren nhanh khac)
Xong. Doi model sau nay: leader giao goi moi -> 'python -m aiws_ci.model_tool lock <goi> --out ci/model-lock.json'
tren may dev, mo merge request; tren Server 3 chay lai script nay voi goi moi (khong can build lai anh neu ma khong doi).
EOF
