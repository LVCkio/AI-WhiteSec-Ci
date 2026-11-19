#!/usr/bin/env bash
# Server 3 - build lai CA HAI anh cua Pipeline 2 tu CUNG mot commit (19/11/2026).
# Ly do: P1 (anh aiws-codebert) va P2 Semgrep (anh aiws-semgrep) cung chon pham vi file bang scan_repo.py +
#   .semgrepignore DONG GOI TRONG ANH. Hai anh build tu hai commit khac nhau -> hai ben nhin hai tap file khac
#   nhau (P4 se canh bao "scope_signature" lech). Dung sau moi lan sua rule, scan_repo.py, .semgrepignore
#   hoac ma ci/aiws_ci/*.py.
# Dung:  sudo bash ci/servers/server3_rebuild_images.sh <thu muc repo AI-WhiteSec-Ci (da git pull)>
set -euo pipefail

SRC="${1:-}"
if [[ -z "$SRC" ]]; then echo "Dung: sudo bash $0 <thu muc AI-WhiteSec-Ci>"; exit 1; fi
SRC=$(realpath "$SRC")
MANIFEST="$SRC/security-config/semgrep/ruleset-manifest.json"
RV=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['ruleset_version'])" "$MANIFEST")
SV=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['semgrep_version_pinned'])" "$MANIFEST")
SEM_IMG="aiws-semgrep:${RV}-semgrep${SV}"
CB_IMG=$(sed -n 's/^ *AIWS_CODEBERT_IMAGE: *"\([^"]*\)".*/\1/p' "$SRC/ci/pipeline2-worker.yml")
CB_IMG="${CB_IMG:-aiws-codebert:0.1.0}"
COMMIT=$(git -C "$SRC" rev-parse HEAD)
if [[ -n "$(git -C "$SRC" status --porcelain --untracked-files=no)" ]]; then
  echo "Repo co thay doi chua commit -> anh se khong khop commit nao. git stash / git checkout truoc."; exit 1; fi

echo "== Commit $COMMIT: build $SEM_IMG va $CB_IMG =="
( cd "$SRC" && DOCKER_BUILDKIT=1 docker build --label "aiws.commit=$COMMIT" \
    -f security-config/semgrep/ci/Dockerfile -t "$SEM_IMG" . )
( cd "$SRC" && DOCKER_BUILDKIT=1 docker build --label "aiws.commit=$COMMIT" \
    -f ci/docker/Dockerfile.codebert -t "$CB_IMG" . )

echo "== Kiem: hai anh chon pham vi file giong nhau (scope_signature) =="
SIG='import importlib.util as u,sys; s=u.spec_from_file_location("s",sys.argv[1]); m=u.module_from_spec(s); s.loader.exec_module(m); print(m.scope_signature(m.load_ignore(m.IGNORE_FILE)))'
A=$(docker run --rm --entrypoint python "$SEM_IMG" -c "$SIG" /opt/aiws/security-config/semgrep/tools/scan_repo.py)
B=$(docker run --rm --entrypoint python "$CB_IMG" -c "$SIG" /opt/aiws/security-config/semgrep/tools/scan_repo.py)
echo "  $SEM_IMG : $A"; echo "  $CB_IMG : $B"
[[ "$A" == "$B" ]] || { echo "LECH scope_signature -> kiem lai Dockerfile hai anh"; exit 1; }
for i in "$SEM_IMG" "$CB_IMG"; do
  echo "  $i <- commit $(docker image inspect -f '{{ index .Config.Labels "aiws.commit" }}' "$i")"; done
echo "Xong. Neu doi ruleset_version: sua AIWS_RULESET_VERSION / AIWS_SEMGREP_IMAGE trong"
echo "security-config/semgrep/ci/gitlab-ci-semgrep.yml cho khop $SEM_IMG."
