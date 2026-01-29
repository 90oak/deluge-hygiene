#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "ERROR: must be run as root." >&2
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="/root/disable_llmnr_${TS}"
mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_DIR/run.log") 2>&1

echo "==> Logging to $LOG_DIR"

echo "==> Preflight checks"
if ! command -v ss >/dev/null 2>&1; then
  echo "ERROR: ss command not found." >&2
  exit 1
fi

echo "-- Baseline listeners"
ss -tulnp | tee "$LOG_DIR/ss_before.txt"

echo "-- Baseline resolver status"
if command -v resolvectl >/dev/null 2>&1; then
  resolvectl status | tee "$LOG_DIR/resolvectl_before.txt"
else
  echo "resolvectl not found" | tee "$LOG_DIR/resolvectl_before.txt"
fi

echo "-- Baseline /etc/resolv.conf"
cat /etc/resolv.conf | tee "$LOG_DIR/resolv.conf_before.txt"

echo "-- Baseline DNS resolution"
getent hosts deb.debian.org | tee "$LOG_DIR/getent_deb_before.txt"
getent hosts github.com | tee "$LOG_DIR/getent_github_before.txt"

echo "==> Disabling LLMNR and MulticastDNS"
DROPIN_DIR="/etc/systemd/resolved.conf.d"
DROPIN_FILE="$DROPIN_DIR/disable-llmnr-mdns.conf"
mkdir -p "$DROPIN_DIR"

if [[ -f "$DROPIN_FILE" ]]; then
  cp -a "$DROPIN_FILE" "$LOG_DIR/disable-llmnr-mdns.conf.bak"
  echo "Backed up existing drop-in to $LOG_DIR/disable-llmnr-mdns.conf.bak"
fi

cat <<'CONF' > "$DROPIN_FILE"
[Resolve]
LLMNR=no
MulticastDNS=no
CONF

echo "Wrote $DROPIN_FILE"

echo "==> Restarting systemd-resolved"
systemctl restart systemd-resolved
systemctl is-active systemd-resolved

echo "==> Verifying port 5355 is not listening"
ss -tulnp | tee "$LOG_DIR/ss_after.txt"
if ss -tulnp | grep -E ':(5355)\b' >/dev/null 2>&1; then
  echo "ERROR: listeners still present on port 5355" >&2
  exit 1
fi

echo "==> Post-change DNS resolution"
getent hosts deb.debian.org | tee "$LOG_DIR/getent_deb_after.txt"
getent hosts github.com | tee "$LOG_DIR/getent_github_after.txt"

echo "==> Running apt-get update"
apt-get update -o Acquire::ForceIPv4=false | tee "$LOG_DIR/apt_update.txt"

echo "==> Summary"
echo "-- Listeners before:"; cat "$LOG_DIR/ss_before.txt"
echo "-- Listeners after:"; cat "$LOG_DIR/ss_after.txt"

echo "-- Resolver status before:"; cat "$LOG_DIR/resolvectl_before.txt"
if command -v resolvectl >/dev/null 2>&1; then
  echo "-- Resolver status after:"; resolvectl status | tee "$LOG_DIR/resolvectl_after.txt"
fi

echo "==> Rollback instructions"
if [[ -f "$LOG_DIR/disable-llmnr-mdns.conf.bak" ]]; then
  echo "1) Restore the previous drop-in: cp -a $LOG_DIR/disable-llmnr-mdns.conf.bak $DROPIN_FILE"
else
  echo "1) Remove the drop-in: rm -f $DROPIN_FILE"
fi

echo "2) Restart systemd-resolved: systemctl restart systemd-resolved"

echo "Done."
