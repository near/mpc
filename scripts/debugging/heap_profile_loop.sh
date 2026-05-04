#!/usr/bin/env bash
# Periodically fetch a jemalloc heap pprof from a running mpc-node and save it
# to disk. Designed to run detached on a host with no tmux/screen.
#
# Launch (survives ssh logout):
#   setsid nohup /path/to/heap_profile_loop.sh > /dev/null 2>&1 < /dev/null &
#   disown
#
# Stop:
#   kill "$(cat "$PID_FILE")"

set -u

ENDPOINT="${ENDPOINT:-http://127.0.0.1:34001/profiler/jemalloc/heap}"
INTERVAL_SECS="${INTERVAL_SECS:-300}"            # 5 minutes
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/heap_profiles}"
RETENTION="${RETENTION:-288}"                    # keep ~24h at 5min cadence
CURL_TIMEOUT_SECS="${CURL_TIMEOUT_SECS:-120}"
LOG_FILE="${LOG_FILE:-$OUTPUT_DIR/loop.log}"
PID_FILE="${PID_FILE:-$OUTPUT_DIR/loop.pid}"

mkdir -p "$OUTPUT_DIR"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "already running as PID $(cat "$PID_FILE")" >&2
  exit 1
fi
echo $$ > "$PID_FILE"

log() {
  printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$LOG_FILE"
}

cleanup() {
  log "stopping (signal received)"
  rm -f "$PID_FILE"
  exit 0
}
trap cleanup INT TERM

log "starting endpoint=$ENDPOINT interval=${INTERVAL_SECS}s out=$OUTPUT_DIR retention=$RETENTION"

while true; do
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  out="$OUTPUT_DIR/heap_${ts}.pb.gz"
  tmp="${out}.tmp"

  http_code="$(curl --silent --show-error --fail \
    --max-time "$CURL_TIMEOUT_SECS" \
    --output "$tmp" \
    --write-out '%{http_code}' \
    "$ENDPOINT" 2>>"$LOG_FILE")" || http_code="curl_error"

  if [[ "$http_code" == "200" && -s "$tmp" ]]; then
    mv "$tmp" "$out"
    size="$(stat -c %s "$out" 2>/dev/null || echo ?)"
    log "saved $out ($size bytes)"
  else
    rm -f "$tmp"
    log "fetch failed http=$http_code"
  fi

  # Retention: keep the newest $RETENTION heap_*.pb.gz files.
  mapfile -t old < <(ls -1t "$OUTPUT_DIR"/heap_*.pb.gz 2>/dev/null | tail -n +"$((RETENTION + 1))")
  if (( ${#old[@]} > 0 )); then
    rm -f "${old[@]}"
    log "pruned ${#old[@]} old profile(s)"
  fi

  sleep "$INTERVAL_SECS"
done
