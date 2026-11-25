#!/usr/bin/env bash
# MAU deploy.sh cho project can quet (CD 25/11/2026). Chep vao goc project, dat ten deploy.sh, chmod +x.
#   ./deploy.sh staging      - build anh tu commit nay, chay container <project>-staging
#   ./deploy.sh production   - KHONG build lai: day DUNG anh da chay o staging (cung commit) sang <project>-production
# Chay tren runner tag aiws-deploy (shell runner co Docker). Chi mo cong tren IP noi bo / WireGuard (DEPLOY_BIND_IP),
# khong bao gio 0.0.0.0 - ung dung demo co the co lo hong co y.
set -euo pipefail
ENV=${1:?Dung: $0 staging|production}
case "$ENV" in
  staging)    PORT=${STAGING_PORT:-8081} ;;
  production) PORT=${PROD_PORT:-8082} ;;
  *) echo "Moi truong khong hop le: $ENV"; exit 2 ;;
esac
BIND=${DEPLOY_BIND_IP:-127.0.0.1}
APP_PORT=${APP_PORT:-8000}
P=$(echo "${CI_PROJECT_NAME:-app}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_.\n-' '-')
SHA=${CI_COMMIT_SHORT_SHA:-local}
STAGING_IMG="$P:staging-$SHA"

if [ "$ENV" = staging ]; then
  docker build --label "aiws.commit=${CI_COMMIT_SHA:-}" --label "aiws.run=${AIWS_RUN_ID:-}" -t "$STAGING_IMG" .
  IMG="$STAGING_IMG"
else
  docker image inspect "$STAGING_IMG" >/dev/null 2>&1 || {
    echo "Chua co anh $STAGING_IMG (commit nay chua len staging tren may nay) - khong deploy production"; exit 1; }
  IMG="$P:production-$SHA"
  docker tag "$STAGING_IMG" "$IMG"
fi

NAME="$P-$ENV"
PREV=$(docker inspect -f '{{.Config.Image}}' "$NAME" 2>/dev/null || true)
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --restart unless-stopped -p "$BIND:$PORT:$APP_PORT" \
  --label "aiws.env=$ENV" --label "aiws.commit=${CI_COMMIT_SHA:-}" "$IMG" >/dev/null

for i in $(seq 1 30); do                       # cho ung dung len (toi da ~60 s)
  if curl -fsS -m 3 -o /dev/null "http://$BIND:$PORT${HEALTH_PATH:-/}"; then
    echo "$ENV: $IMG chay o http://$BIND:$PORT"; exit 0
  fi
  sleep 2
done
echo "$ENV: ung dung khong tra loi - quay lai ban truoc (${PREV:-khong co})"
docker logs --tail 30 "$NAME" || true
docker rm -f "$NAME" >/dev/null 2>&1 || true
[ -n "$PREV" ] && docker run -d --name "$NAME" --restart unless-stopped -p "$BIND:$PORT:$APP_PORT" "$PREV" >/dev/null
exit 1
