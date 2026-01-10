#!/usr/bin/env bash
set -euo pipefail

LOG=/var/log/deluge-hygiene.log

# Burst markers
FLAG1=/srv/overflow/.OVERFLOW_ACTIVE
FLAG2=/etc/burst_volume.meta

# Deluge config to detect burst paths
CONF=/var/lib/deluged/config/core.conf

# Python + your script path
PY="$(command -v python3 || echo /usr/bin/python3)"
SCRIPT="/root/remove_oversized_torrents.py"

# If script missing, don’t spam cron—just log and exit cleanly
if [[ ! -f "$SCRIPT" ]]; then
  echo "$(date -Is) [SKIP] $SCRIPT not found" >> "$LOG"
  exit 0
fi

# Skip if burst storage is active
if [[ -e "$FLAG1" || -e "$FLAG2" ]] || findmnt -rn /srv/overflow >/dev/null 2>&1; then
  echo "$(date -Is) [SKIP] burst mode active" >> "$LOG"
  exit 0
fi

# Skip if Deluge is configured to use overflow paths (requires jq, but degrades gracefully)
if command -v jq >/dev/null 2>&1 && [[ -f "$CONF" ]]; then
  if jq -e '
      .download_location=="/srv/overflow/incomplete"
      or .move_completed_path=="/var/lib/deluged/Finished/_overflow"
    ' "$CONF" >/dev/null 2>&1; then
    echo "$(date -Is) [SKIP] deluge in burst config" >> "$LOG"
    exit 0
  fi
fi

# Run the hygiene script (non-overlapping)
exec flock -n /run/deluge-hygiene.lock "$PY" "$SCRIPT" "$@" >> "$LOG" 2>&1
