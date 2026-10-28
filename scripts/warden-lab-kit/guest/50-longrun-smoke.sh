#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/lab-common.sh
source "$ROOT/lib/lab-common.sh"
lab_load_config "$ROOT"; lab_validate_config
INTERVAL="${1:-60}"; HOURS="${2:-8}"
[[ "$INTERVAL" =~ ^[0-9]+$ && "$INTERVAL" -ge 10 ]] || { echo 'Interval must be an integer >= 10 seconds.' >&2; exit 2; }
[[ "$HOURS" =~ ^[0-9]+$ && "$HOURS" -ge 1 && "$HOURS" -le 168 ]] || { echo 'Duration must be 1..168 hours.' >&2; exit 2; }
command -v curl >/dev/null || lab_die 'curl is required'
OUTDIR="$ROOT/results"; install -d -m 0750 "$OUTDIR"
OUT="$OUTDIR/waf-smoke-$(date +%Y%m%d-%H%M%S).csv"
printf 'timestamp,probe,expected_code,http_code,time_seconds\n' > "$OUT"
END=$((SECONDS + HOURS * 3600)); FAILURES=0; PROBES=0
printf 'Logging to %s; interval=%ss; duration=%sh (Ctrl-C to stop).\n' "$OUT" "$INTERVAL" "$HOURS"
while (( SECONDS < END )); do
  TS="$(date --iso-8601=seconds)"
  for spec in \
    'health|200|http|/health.php' \
    'https-health|200|https|/health.php' \
    'xss|403|http|/xss.php?q=%3Cscript%3Ealert(1)%3C/script%3E' \
    'sqli|403|http|/sqli.php?id=1%20OR%201=1' \
    'traversal|403|http|/traversal.php?file=../../../../../etc/passwd'; do
    IFS='|' read -r NAME EXPECTED SCHEME PATH_Q <<< "$spec"
    EXTRA=(); [[ "$SCHEME" == https ]] && EXTRA=(-k)
    if RESULT="$(curl --interface "$LAB_IP" --noproxy '*' "${EXTRA[@]}" -sS --connect-timeout 3 --max-time 8 -o /dev/null -w '%{http_code},%{time_total}' "${SCHEME}://${LAB_IP}${PATH_Q}" 2>/dev/null)"; then :; else RESULT='000,0'; fi
    CODE="${RESULT%%,*}"; TIME="${RESULT#*,}"
    printf '%s,%s,%s,%s,%s\n' "$TS" "$NAME" "$EXPECTED" "$CODE" "$TIME" >> "$OUT"
    printf '%s %-12s HTTP %s (expected %s) %ss\n' "$TS" "$NAME" "$CODE" "$EXPECTED" "$TIME"
    ((PROBES+=1)); [[ "$CODE" == "$EXPECTED" ]] || ((FAILURES+=1))
  done
  sleep "$INTERVAL"
done
printf '\nFinished: %s\nProbes: %s\nFailures: %s\n' "$OUT" "$PROBES" "$FAILURES"
(( FAILURES == 0 )) || exit 1
