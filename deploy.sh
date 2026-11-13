#!/usr/bin/env sh
# Oppdater og start på nytt på Pi-en. Kan kjøres fra hvor som helst.
# Profiler (f.eks. tunnel) velges med COMPOSE_PROFILES=... i .env.
set -e
cd "$(dirname "$0")"
git pull --ff-only

# Versjon og byggetidspunkt som vises i appen. Settes av familiesidens oppdater-alle.sh,
# og av byggeinfo.sh her når skriptet kjøres for hånd. PR-en slås opp på GitHub fra commiten,
# uavhengig av commitmeldingene (repoet er offentlig, så det trengs ikke noe token).
[ -n "${BYGG_COMMIT:-}" ] || . ./byggeinfo.sh
echo "Byggeinfo: commit $BYGG_COMMIT, PR ${BYGG_PR:-ingen}, bygget $BYGG_TID"

# OMSTART=1 (valgt app i familiesidens workflow) lager containeren på nytt selv om ingenting er endret.
if [ "${OMSTART:-}" = 1 ]; then
  docker compose up -d --build --force-recreate
else
  docker compose up -d --build
fi
docker image prune -f >/dev/null
echo "shodan-sok er bygget og startet"
