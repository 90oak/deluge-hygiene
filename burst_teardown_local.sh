#!/usr/bin/env bash
# Teardown burst storage (LOCAL).
# - Unbind & unmount
# - OFFLINE: revert /var/lib/deluged/config/core.conf to base paths
# - Detach and delete the SBS Block Volume (always)

set -euo pipefail
export PATH=/usr/sbin:/sbin:/usr/bin:/bin:$PATH

require_root() { [[ $(id -u) -eq 0 ]] || { echo "Please run as root (sudo)."; exit 1; }; }
have()        { command -v "$1" >/dev/null 2>&1; }
die()         { echo "ERROR: $*" >&2; exit 1; }

require_root
for b in scw jq lsblk findmnt mount umount systemctl; do have "$b" || { echo "Missing binary: $b"; exit 1; }; done

# ---------- Paths & users ----------
DOWNLOAD_DIR="/var/lib/deluged/Downloads"
FINISHED_DIR="/var/lib/deluged/Finished"
OVERFLOW_MOUNT="/srv/overflow"
COMPLETED_SRC="${OVERFLOW_MOUNT}/completed"
INCOMPLETE_SRC="${OVERFLOW_MOUNT}/incomplete"
BIND_TARGET="${FINISHED_DIR}/_overflow"

OVERFLOW_FLAG="${OVERFLOW_MOUNT}/.OVERFLOW_ACTIVE"

DELUGE_USER_SYS="debian-deluged"
DELUGE_CORE_CONF="/var/lib/deluged/config/core.conf"

# ---------- Scaleway ----------
ZONE="${SCW_DEFAULT_ZONE:-nl-ams-1}"
SERVER_ID=""

# ---------- Sanity: overflow must be empty ----------
echo "Checking that overflow directories are empty…"
if [[ -d "${OVERFLOW_MOUNT}" ]]; then
  if find "${OVERFLOW_MOUNT}" -mindepth 1 -type f ! -name ".OVERFLOW_ACTIVE" -print -quit | grep -q .; then
    die "Overflow mount contains files. Remove them before tearing down."
  fi
fi
for dir in "${COMPLETED_SRC}" "${INCOMPLETE_SRC}"; do
  if [[ -d "${dir}" ]] && find "${dir}" -mindepth 1 -print -quit | grep -q .; then
    die "${dir} is not empty. Move or delete contents before tearing down."
  fi
done

# ---------- Capture mount source before unmount ----------
SRC_BEFORE="$(findmnt -no SOURCE "${OVERFLOW_MOUNT}" 2>/dev/null || true)"

echo "Unbinding ${BIND_TARGET}…"
mountpoint -q "${BIND_TARGET}" && umount "${BIND_TARGET}" || true

echo "Unmounting ${OVERFLOW_MOUNT}…"
mountpoint -q "${OVERFLOW_MOUNT}" && umount "${OVERFLOW_MOUNT}" || true

rm -f "${OVERFLOW_FLAG}"

# ---------- OFFLINE: revert Deluge config ----------
if [[ -f "${DELUGE_CORE_CONF}" ]]; then
  echo "==> Reverting Deluge defaults in ${DELUGE_CORE_CONF}"
  systemctl stop deluged || true
  cp -n "${DELUGE_CORE_CONF}" "${DELUGE_CORE_CONF}.bak.$(date +%s)" || true
  jq --arg dl "${DOWNLOAD_DIR}" --arg mp "${FINISHED_DIR}" -c \
    '.download_location=$dl | .move_completed=true | .move_completed_path=$mp' \
    "${DELUGE_CORE_CONF}" > "${DELUGE_CORE_CONF}.new"
  mv "${DELUGE_CORE_CONF}.new" "${DELUGE_CORE_CONF}"
  chown "${DELUGE_USER_SYS}:${DELUGE_USER_SYS}" "${DELUGE_CORE_CONF}" 2>/dev/null || true
  chmod 600 "${DELUGE_CORE_CONF}" 2>/dev/null || true
  systemctl start deluged || true
else
  echo "WARN: ${DELUGE_CORE_CONF} not found; skipping Deluge revert."
fi

# ---------- Determine VOL_ID (marker -> mount -> fallback) ----------
VOL_ID=""
if [[ -f /etc/burst_volume.meta ]]; then
  read -r VOL_ID ZONE_FROM_FILE < /etc/burst_volume.meta || true
  [[ -n "${ZONE_FROM_FILE:-}" ]] && ZONE="${ZONE_FROM_FILE}"
fi

if [[ -z "${VOL_ID}" && -n "${SRC_BEFORE}" ]]; then
  DEV_REAL="$(readlink -f "${SRC_BEFORE}" || true)"
  if [[ -n "${DEV_REAL}" ]]; then
    SER="$(lsblk -no SERIAL "${DEV_REAL}" 2>/dev/null || true)"
    [[ -z "${SER}" ]] && SER="$(lsblk -S -o NAME,SERIAL | awk -v d="$(basename "${DEV_REAL}")" '$1==d{print $2; exit}')"
    VOL_ID="${SER#volume-}"
  fi
fi

if [[ -z "${VOL_ID}" ]]; then
  VOL_ID="$(scw block volume list zone=${ZONE} -o json | jq -r '.[] | select(.status=="in_use") | .id' | head -n1 || true)"
fi

if [[ -z "${VOL_ID}" ]]; then
  die "Could not determine Scaleway volume ID automatically."
fi

# ---------- Detect server-id if needed ----------
if [[ -z "$SERVER_ID" ]]; then
  if command -v curl >/dev/null && curl -fsS --connect-timeout 1 http://169.254.42.42/conf?format=json >/dev/null; then
    SERVER_ID="$(curl -fsS http://169.254.42.42/conf?format=json | jq -r '.ID // empty')"
    META_ZONE="$(curl -fsS http://169.254.42.42/conf?format=json | jq -r '.ZONE // empty')" || true
    [[ -n "${META_ZONE}" ]] && ZONE="${META_ZONE}"
  fi
  if [[ -z "$SERVER_ID" ]]; then
    HN="$(hostname)"
    SERVER_ID="$(scw instance server list zone=${ZONE} -o json | jq -r ".[] | select(.name==\"${HN}\") | .id")" || true
  fi
fi
[[ -n "$SERVER_ID" ]] || die "Could not determine server-id."

# ---------- Detach and delete ----------
echo "Detaching volume ${VOL_ID} from server ${SERVER_ID} (zone ${ZONE})…"
scw instance server detach-volume server-id="${SERVER_ID}" volume-id="${VOL_ID}" zone=${ZONE} >/dev/null
scw block volume wait "${VOL_ID}" zone=${ZONE} terminal-status=available >/dev/null
echo "Detached."

echo "Deleting volume ${VOL_ID}…"
scw block volume delete "${VOL_ID}" zone=${ZONE} >/dev/null
echo "Deleted."

rm -f /etc/burst_volume.meta

echo "Removing bind target ${BIND_TARGET}…"
rm -rf "${BIND_TARGET}"

echo "✅ Teardown complete."
