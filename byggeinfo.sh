#!/usr/bin/env sh
# Setter byggeinfo for appen i mappa $BYGG_MAPPE (standard: denne mappa) som miljøvariabler:
#   BYGG_COMMIT       kort commit-hash
#   BYGG_COMMIT_DATO  når commiten ble laget (ISO 8601)
#   BYGG_PR           nummeret på PR-en som ga denne versjonen (tomt hvis ingen)
#   BYGG_TID          når bygget startet (ISO 8601)
# Leses inn med «BYGG_MAPPE=mappe; . byggeinfo.sh» av oppdater-alle.sh og standard-deploy.sh før docker compose bygger.
# Appenes docker-compose.yml sender variablene videre som build args, og Dockerfile lager /versjon.json av dem,
# på samme måte som familiesiden viser «Versjon ... · bygget ...».
#
# PR-nummeret hentes fra GitHub (GET /repos/{eier}/{repo}/commits/{sha}/pulls), så det er uavhengig av hva
# commitmeldingene heter, og virker for vanlig merge, squash og rebase. Er HEAD pushet rett til main uten PR,
# brukes PR-en til nærmeste commit før den. Private repoer trenger et token: BYGG_GH_TOKEN, GH_TOKEN eller
# GITHUB_TOKEN, ellers «gh auth token» eller git sitt lagrede passord for github.com. Svarer ikke GitHub,
# leses nummeret fra commitmeldingene som før, og finnes det ikke der heller, blir BYGG_PR tom («ingen»).
# Samme fil ligger i alle appene (byggeinfo.sh), så den kan kopieres uendret.
_bygg_mappe="${BYGG_MAPPE:-.}"
BYGG_COMMIT="$(git -C "$_bygg_mappe" rev-parse --short HEAD 2>/dev/null || true)"
BYGG_COMMIT_DATO="$(git -C "$_bygg_mappe" log -1 --format=%cI 2>/dev/null || true)"
BYGG_TID="$(date -Iseconds)"

# Første PR-nummer i et svar fra commits/{sha}/pulls, helst en som er merget.
_bygg_pr_fra_json() {
  if command -v jq >/dev/null 2>&1; then
    jq -r '([.[] | select(.merged_at != null)] + .)[0].number // empty' 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    p = [x for x in d if x.get("merged_at")] + d
    print(p[0]["number"] if p else "")
except Exception:
    pass' 2>/dev/null
  else
    grep -oE '"html_url": *"https://github.com/[^"]+/pull/[0-9]+"' | head -n 1 | grep -oE '[0-9]+"$' | tr -d '"'
  fi
}

_bygg_token() {
  _t="${BYGG_GH_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"
  [ -n "$_t" ] || { command -v gh >/dev/null 2>&1 && _t="$(gh auth token 2>/dev/null)"; } || true
  [ -n "$_t" ] || _t="$(printf 'protocol=https\nhost=github.com\n\n' \
    | GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=true SSH_ASKPASS=true git credential fill 2>/dev/null | sed -n 's/^password=//p')" || true
  printf '%s' "$_t"
}

_bygg_pr_fra_github() {
  _repo="$(git -C "$_bygg_mappe" remote get-url origin 2>/dev/null \
    | sed -nE 's#^.*github\.com[:/]+([^/]+/[^/]+)$#\1#p' | sed 's/\.git$//')"
  [ -n "$_repo" ] && command -v curl >/dev/null 2>&1 || return 0
  _tok="$(_bygg_token)"
  for _sha in $(git -C "$_bygg_mappe" rev-list --first-parent -n 10 HEAD 2>/dev/null); do
    if [ -n "$_tok" ]; then
      _svar="$(curl -fsS --max-time 8 -H 'Accept: application/vnd.github+json' -H "Authorization: Bearer $_tok" \
        "https://api.github.com/repos/$_repo/commits/$_sha/pulls" 2>/dev/null)" || return 0
    else
      _svar="$(curl -fsS --max-time 8 -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/$_repo/commits/$_sha/pulls" 2>/dev/null)" || return 0
    fi
    _nr="$(printf '%s' "$_svar" | _bygg_pr_fra_json)"
    case "$_nr" in ''|*[!0-9]*) ;; *) printf '%s' "$_nr"; return 0 ;; esac
  done
}

BYGG_PR="$(_bygg_pr_fra_github)"
# Reserve når GitHub ikke svarer: «Merge pull request #12 ...» (vanlig merge) eller «Tittel (#12)» (squash).
[ -n "$BYGG_PR" ] || BYGG_PR="$(git -C "$_bygg_mappe" log -200 --format=%s 2>/dev/null \
  | sed -nE 's/^Merge pull request #([0-9]+).*/\1/p; s/.*\(#([0-9]+)\)$/\1/p' | head -n 1)"
export BYGG_COMMIT BYGG_COMMIT_DATO BYGG_PR BYGG_TID
unset _bygg_mappe _t _repo _tok _sha _svar _nr
unset -f _bygg_pr_fra_json _bygg_token _bygg_pr_fra_github 2>/dev/null || true
