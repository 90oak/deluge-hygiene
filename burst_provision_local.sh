#!/usr/bin/env bash
# Provision burst storage on a Scaleway Debian instance (LOCAL).
# - Creates & attaches an SBS Block Volume
# - Mounts at /srv/overflow
# - Binds /srv/overflow/completed -> /var/lib/deluged/Finished/_overflow
# - OFFLINE: patches /var/lib/deluged/config/core.conf to use split paths

set -euo pipefail
export PATH=/usr/sbin:/sbin:/usr/bin:/bin:$PATH

require_root() { [[ $(id -u) -eq 0 ]] || { echo "Please run as root (sudo)."; exit 1; }; }
have()        { command -v "$1" >/dev/null 2>&1; }

require_root
for b in scw jq lsblk blkid mount umount systemctl; do have "$b" || { echo "Missing binary: $b"; exit 1; }; done

# ---------- Defaults (edit here to change behavior) ----------
SIZE_GB=""                                  # REQUIRED CLI arg
ZONE="${SCW_DEFAULT_ZONE:-nl-ams-1}"        # e.g. nl-ams-1
NAME_PREFIX="overflow"                      # Used for volume name prefix
IOPS="5000"                                 # 5000 or 15000
FS="xfs"                                    # xfs|ext4

DOWNLOAD_DIR="/var/lib/deluged/Downloads"
FINISHED_DIR="/var/lib/deluged/Finished"
OVERFLOW_MOUNT="/srv/overflow"
DELUGE_USER_SYS="debian-deluged"
DELUGE_CORE_CONF="/var/lib/deluged/config/core.conf"

WRITE_FSTAB=false                            # Toggle to emit fstab entries automatically
ENABLE_BURST=true                            # Toggle to rewrite Deluge config for burst

SERVER_ID=""                                 # Auto-detected unless set here

usage() {
  cat <<EOF
Usage: $0 <size-gb>
   or: $0 --size-gb <size>

Examples:
  sudo $0 600
  sudo $0 --size-gb 400

All other knobs are hardcoded at the top of this script; adjust them here when needed.
EOF
  exit 2
}

# ---------- Args ----------
if [[ $# -eq 1 ]]; then
  [[ "$1" == "-h" || "$1" == "--help" ]] && usage
  SIZE_GB="$1"
elif [[ $# -eq 2 && "$1" == "--size-gb" ]]; then
  SIZE_GB="$2"
else
  usage
fi

NAME="${NAME_PREFIX}-$(date +%s)"
[[ -n "${SIZE_GB}" ]] || usage
[[ "${IOPS}" == "5000" || "${IOPS}" == "15000" ]] || { echo "IOPS must be 5000 or 15000"; exit 1; }
[[ "${FS}" == "xfs" || "${FS}" == "ext4" ]] || { echo "FS must be xfs or ext4"; exit 1; }

# Derived paths (bind target & split dirs)
BIND_TARGET="${FINISHED_DIR}/_overflow"
COMPLETED_SRC="${OVERFLOW_MOUNT}/completed"
INCOMPLETE_SRC="${OVERFLOW_MOUNT}/incomplete"

# ---------- Detect server-id / zone ----------
if [[ -z "${SERVER_ID}" ]]; then
  if have curl && curl -fsS --connect-timeout 1 http://169.254.42.42/conf?format=json >/dev/null; then
    SERVER_ID="$(curl -fsS http://169.254.42.42/conf?format=json | jq -r '.ID // empty')"
    META_ZONE="$(curl -fsS http://169.254.42.42/conf?format=json | jq -r '.ZONE // empty')" || true
    [[ -n "${META_ZONE}" ]] && ZONE="${META_ZONE}"
  fi
  if [[ -z "${SERVER_ID:-}" ]]; then
    HN="$(hostname)"
    SERVER_ID="$(scw instance server list zone=${ZONE} -o json | jq -r ".[] | select(.name==\"${HN}\") | .id")" || true
  fi
fi
[[ -n "${SERVER_ID}" ]] || { echo "Could not determine server-id. Pass --server-id <ID>."; exit 1; }

# ---------- Create & attach volume ----------
echo "==> Creating ${SIZE_GB}G volume '${NAME}' in ${ZONE} (IOPS ${IOPS})"
VOL_JSON="$(scw block volume create name="${NAME}" from-empty.size="${SIZE_GB}G" perf-iops="${IOPS}" zone=${ZONE} -o json)"
VOL_ID="$(echo "${VOL_JSON}" | jq -r '.id')"
[[ -n "${VOL_ID}" && "${VOL_ID}" != "null" ]] || { echo "Failed to create volume"; exit 1; }
scw block volume wait "${VOL_ID}" zone=${ZONE} terminal-status=available >/dev/null

echo "==> Attaching volume ${VOL_ID} to server ${SERVER_ID}"
scw instance server attach-volume server-id="${SERVER_ID}" volume-id="${VOL_ID}" volume-type=sbs_volume zone=${ZONE} >/dev/null
scw block volume wait "${VOL_ID}" zone=${ZONE} terminal-status=in_use >/dev/null

# Persist the volume identity for teardown
echo "${VOL_ID} ${ZONE}" > /etc/burst_volume.meta
chmod 600 /etc/burst_volume.meta

# ---------- Resolve device ----------
echo "==> Resolving device for volume ${VOL_ID}"
DEV_NAME=""
for _ in {1..30}; do
  DEV_NAME="$(lsblk -S -o NAME,SERIAL | awk -v v="volume-${VOL_ID}" '$2==v{print $1; exit}')"
  [[ -n "${DEV_NAME}" ]] && break
  sleep 1
done
[[ -n "${DEV_NAME}" ]] || { echo "Could not find block device for volume ${VOL_ID}"; exit 1; }
DEV_PATH="/dev/${DEV_NAME}"
echo "    Device: ${DEV_PATH}"

# ---------- FS, mount, bind (correct order) ----------
if ! blkid "${DEV_PATH}" >/dev/null 2>&1; then
  echo "==> Creating ${FS} filesystem on ${DEV_PATH}"
  case "${FS}" in
    xfs)  mkfs.xfs -f "${DEV_PATH}" ;;
    ext4) mkfs.ext4 -F "${DEV_PATH}" ;;
  esac
fi

echo "==> Mounting ${DEV_PATH} at ${OVERFLOW_MOUNT}"
mkdir -p "${OVERFLOW_MOUNT}"
mountpoint -q "${OVERFLOW_MOUNT}" || mount "${DEV_PATH}" "${OVERFLOW_MOUNT}"

# Create split dirs *after* mount, then bind only "completed"
mkdir -p "${COMPLETED_SRC}" "${INCOMPLETE_SRC}" "${BIND_TARGET}"
mountpoint -q "${BIND_TARGET}" || mount --bind "${COMPLETED_SRC}" "${BIND_TARGET}"

# Ownership for Deluge daemon
if id "${DELUGE_USER_SYS}" >/dev/null 2>&1; then
  chown -R "${DELUGE_USER_SYS}:${DELUGE_USER_SYS}" "${OVERFLOW_MOUNT}" "${BIND_TARGET}"
fi
: > "${OVERFLOW_MOUNT}/.OVERFLOW_ACTIVE"

# ---------- fstab (optional) ----------
UUID="$(blkid -s UUID -o value "${DEV_PATH}")"
FSTAB_DEV="UUID=${UUID}  ${OVERFLOW_MOUNT}  ${FS}  noatime,nofail  0 2"
FSTAB_BIND="${COMPLETED_SRC}  ${BIND_TARGET}  none  bind  0 0"

echo
echo "Add to /etc/fstab (recommended):"
echo "  ${FSTAB_DEV}"
echo "  ${FSTAB_BIND}"
if ${WRITE_FSTAB}; then
  echo "==> Writing fstab entries (backup at /etc/fstab.burstbak)"
  cp -n /etc/fstab /etc/fstab.burstbak || true
  grep -qF "${FSTAB_DEV}"  /etc/fstab || echo "${FSTAB_DEV}"  >> /etc/fstab
  grep -qF "${FSTAB_BIND}" /etc/fstab || echo "${FSTAB_BIND}" >> /etc/fstab
fi

# ---------- OFFLINE: flip Deluge to "Burst ON" ----------
if ${ENABLE_BURST}; then
  echo "==> Applying Deluge burst mode via ${DELUGE_CORE_CONF}"
  if [[ ! -f "${DELUGE_CORE_CONF}" ]]; then
    systemctl start deluged || true; sleep 2; systemctl stop deluged || true
  fi
  if [[ -f "${DELUGE_CORE_CONF}" ]]; then
    systemctl stop deluged || true
    cp -n "${DELUGE_CORE_CONF}" "${DELUGE_CORE_CONF}.bak.$(date +%s)" || true
    jq --arg dl "${INCOMPLETE_SRC}" --arg mp "${BIND_TARGET}" -c \
      '.download_location=$dl | .move_completed=true | .move_completed_path=$mp' \
      "${DELUGE_CORE_CONF}" > "${DELUGE_CORE_CONF}.new"
    mv "${DELUGE_CORE_CONF}.new" "${DELUGE_CORE_CONF}"
    chown "${DELUGE_USER_SYS}:${DELUGE_USER_SYS}" "${DELUGE_CORE_CONF}" 2>/dev/null || true
    chmod 600 "${DELUGE_CORE_CONF}" 2>/dev/null || true
    systemctl start deluged || true
  else
    echo "WARN: ${DELUGE_CORE_CONF} not found; skipping Deluge config."
  fi
fi

cat <<EOF

OK ✅  Burst storage provisioned.

Volume:      ${VOL_ID}  (${SIZE_GB}G, IOPS ${IOPS}, zone ${ZONE})
Device:      ${DEV_PATH}
Mounted at:  ${OVERFLOW_MOUNT}
Completed ↔  ${BIND_TARGET}   (bind of ${COMPLETED_SRC})
Incomplete:  ${INCOMPLETE_SRC}  (not visible to rsync on Finished/)
Marker:      /etc/burst_volume.meta  (VOL_ID ZONE)
EOF
