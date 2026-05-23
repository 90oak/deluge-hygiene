#!/usr/bin/env bash
# Manage temporary burst storage for a Trixie Deluge host.
#
# Intended remote entrypoint for an iPhone Shortcut over SSH:
#   sudo -n /usr/local/sbin/deluge-burstctl provision --size-gb 600
#   sudo -n /usr/local/sbin/deluge-burstctl teardown
#   sudo -n /usr/local/sbin/deluge-burstctl status

set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

BASE_DIR="/srv/deluge"
DOWNLOAD_DIR="${BASE_DIR}/Downloads"
FINISHED_DIR="${BASE_DIR}/Finished"
BURST_MOUNT="${BASE_DIR}/.burst"
BURST_COMPLETED="${BURST_MOUNT}/completed"
BURST_INCOMPLETE="${BURST_MOUNT}/incomplete"
BURST_BIND_TARGET="${FINISHED_DIR}/_overflow"
BURST_STATE_DIR="/var/lib/deluge-burst"
BURST_STATE_FILE="${BURST_STATE_DIR}/state.env"
BURST_LOCK="/run/deluge-burst.lock"
BURST_MARKER="${BURST_MOUNT}/.OVERFLOW_ACTIVE"

DELUGE_USER_SYS="debian-deluged"
DELUGE_SERVICE="deluged"
DELUGE_CONFIG_DIR="/var/lib/deluged/config"
DELUGE_CORE_CONF="${DELUGE_CONFIG_DIR}/core.conf"

DEFAULT_ZONE="${SCW_DEFAULT_ZONE:-nl-ams-1}"
DEFAULT_IOPS="5000"
DEFAULT_FS="ext4"
DEFAULT_NAME_PREFIX="deluge-burst"
CONFIG_FILE="${DELUGE_BURST_CONFIG:-/etc/default/deluge-burst}"

COMMAND=""
SIZE_GB=""
ZONE="${DEFAULT_ZONE}"
IOPS="${DEFAULT_IOPS}"
FS="${DEFAULT_FS}"
NAME_PREFIX="${DEFAULT_NAME_PREFIX}"
SERVER_ID=""
ASSUME_YES=0
TAILSCALE_EXIT_NODE=""
TAILSCALE_ALLOW_LAN_ACCESS="true"
TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE="auto"
TAILSCALE_EGRESS_ACTIVE=0
TAILSCALE_STATE_CAPTURED=0
TAILSCALE_WAS_ADVERTISING_EXIT_NODE=0
TAILSCALE_PREVIOUS_EXIT_NODE=""
TAILSCALE_PREVIOUS_ALLOW_LAN_ACCESS="false"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<USAGE
Usage:
  $(basename "$0") provision --size-gb <gb> [--zone <zone>] [--iops 5000|15000] [--fs ext4|xfs] [--name-prefix <prefix>] [--server-id <id>] [--yes]
  $(basename "$0") teardown [--volume-id <id>] [--yes]
  $(basename "$0") repair-active
  $(basename "$0") restore-base
  $(basename "$0") status

Examples:
  sudo $(basename "$0") provision --size-gb 600
  sudo $(basename "$0") provision --size-gb 1200 --iops 15000
  sudo $(basename "$0") teardown

The provision command creates and attaches a Scaleway SBS block volume, mounts it at
${BURST_MOUNT}, sends new incomplete downloads to ${BURST_INCOMPLETE}, moves
completed downloads to ${BURST_COMPLETED}, and exposes them through
${BURST_BIND_TARGET} so the existing rsync "finished" module keeps working.

IPv6-only hosts can set a temporary Tailscale exit node for Scaleway API calls:
  $(basename "$0") provision --size-gb 600 --tailscale-exit-node <node> --yes
or put DELUGE_BURST_TAILSCALE_EXIT_NODE=<node> in ${CONFIG_FILE}.
USAGE
}

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "must be run as root"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

load_config() {
  if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${CONFIG_FILE}"
  fi

  ZONE="${DELUGE_BURST_ZONE:-${ZONE}}"
  SERVER_ID="${DELUGE_BURST_SERVER_ID:-${SERVER_ID}}"
  TAILSCALE_EXIT_NODE="${DELUGE_BURST_TAILSCALE_EXIT_NODE:-${TAILSCALE_EXIT_NODE}}"
  TAILSCALE_ALLOW_LAN_ACCESS="${DELUGE_BURST_TAILSCALE_ALLOW_LAN_ACCESS:-${TAILSCALE_ALLOW_LAN_ACCESS}}"
  TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE="${DELUGE_BURST_TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE:-${TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE}}"
}

is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

require_commands() {
  local missing=()
  local cmd
  for cmd in "$@"; do
    have "$cmd" || missing+=("$cmd")
  done
  if ((${#missing[@]} > 0)); then
    die "missing required command(s): ${missing[*]}"
  fi
}

parse_args() {
  [[ $# -gt 0 ]] || { usage; exit 2; }
  COMMAND="$1"
  shift

  case "${COMMAND}" in
    provision|teardown|repair-active|restore-base|status) ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --size-gb)
        SIZE_GB="${2:-}"
        shift 2
        ;;
      --zone)
        ZONE="${2:-}"
        shift 2
        ;;
      --iops)
        IOPS="${2:-}"
        shift 2
        ;;
      --fs)
        FS="${2:-}"
        shift 2
        ;;
      --name-prefix)
        NAME_PREFIX="${2:-}"
        shift 2
        ;;
      --server-id)
        SERVER_ID="${2:-}"
        shift 2
        ;;
      --volume-id)
        VOL_ID="${2:-}"
        shift 2
        ;;
      --yes|-y)
        ASSUME_YES=1
        shift
        ;;
      --tailscale-exit-node)
        TAILSCALE_EXIT_NODE="${2:-}"
        shift 2
        ;;
      --no-tailscale-exit-node)
        TAILSCALE_EXIT_NODE=""
        shift
        ;;
      --tailscale-allow-lan-access)
        TAILSCALE_ALLOW_LAN_ACCESS="${2:-}"
        shift 2
        ;;
      --tailscale-restore-advertise-exit-node)
        TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option for ${COMMAND}: $1"
        ;;
    esac
  done
}

validate_args() {
  if [[ "${COMMAND}" == "provision" ]]; then
    [[ -n "${SIZE_GB}" ]] || die "provision requires --size-gb"
    [[ "${SIZE_GB}" =~ ^[0-9]+$ ]] || die "--size-gb must be a whole number"
    (( SIZE_GB > 0 )) || die "--size-gb must be greater than zero"
    [[ "${IOPS}" == "5000" || "${IOPS}" == "15000" ]] || die "--iops must be 5000 or 15000"
    [[ "${FS}" == "ext4" || "${FS}" == "xfs" ]] || die "--fs must be ext4 or xfs"
    [[ -n "${ZONE}" ]] || die "--zone cannot be empty"
    [[ -n "${NAME_PREFIX}" ]] || die "--name-prefix cannot be empty"
  fi

  case "${TAILSCALE_ALLOW_LAN_ACCESS,,}" in
    true|false|1|0|yes|no|on|off) ;;
    *) die "--tailscale-allow-lan-access must be true or false" ;;
  esac

  case "${TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE,,}" in
    auto|true|false|1|0|yes|no|on|off) ;;
    *) die "--tailscale-restore-advertise-exit-node must be auto, true, or false" ;;
  esac
}

acquire_lock() {
  exec 9>"${BURST_LOCK}"
  flock -n 9 || die "another burst operation is already running"
}

confirm_cost_action() {
  if [[ "${ASSUME_YES}" -eq 1 ]]; then
    return 0
  fi

  local prompt="$1"
  read -r -p "${prompt} Type yes to continue: " answer
  [[ "${answer}" == "yes" ]] || die "cancelled"
}

python_json_value() {
  local key="$1"
  python3 -c 'import json, sys; data=json.load(sys.stdin); value=data.get(sys.argv[1], ""); print("" if value is None else value)' "${key}"
}

capture_tailscale_state() {
  if [[ "${TAILSCALE_STATE_CAPTURED}" -eq 1 ]]; then
    return 0
  fi

  TAILSCALE_STATE_CAPTURED=1
  local prefs
  prefs="$(tailscale debug prefs 2>/dev/null || true)"
  if [[ -z "${prefs}" ]]; then
    return 0
  fi

  local parsed
  parsed="$(
    printf '%s\n' "${prefs}" | python3 -c '
import json
import sys

try:
    data = json.load(sys.stdin)
except Exception:
    print("|0|false")
    raise SystemExit(0)

routes = data.get("AdvertiseRoutes") or []
advertising = "1" if "0.0.0.0/0" in routes or "::/0" in routes else "0"
exit_node = data.get("ExitNodeID") or data.get("ExitNodeIP") or data.get("ExitNode") or ""
allow_lan = data.get("ExitNodeAllowLANAccess")
if allow_lan is None:
    allow_lan = data.get("AllowLANWhileUsingExitNode", False)
print(f"{exit_node}|{advertising}|{str(bool(allow_lan)).lower()}")
'
  )"

  IFS='|' read -r TAILSCALE_PREVIOUS_EXIT_NODE TAILSCALE_WAS_ADVERTISING_EXIT_NODE TAILSCALE_PREVIOUS_ALLOW_LAN_ACCESS <<<"${parsed}"
  [[ -n "${TAILSCALE_WAS_ADVERTISING_EXIT_NODE}" ]] || TAILSCALE_WAS_ADVERTISING_EXIT_NODE=0
  [[ -n "${TAILSCALE_PREVIOUS_ALLOW_LAN_ACCESS}" ]] || TAILSCALE_PREVIOUS_ALLOW_LAN_ACCESS="false"
}

enable_scaleway_egress() {
  if [[ -z "${TAILSCALE_EXIT_NODE}" || "${TAILSCALE_EGRESS_ACTIVE}" -eq 1 ]]; then
    return 0
  fi

  require_commands tailscale
  capture_tailscale_state

  log "Temporarily using Tailscale exit node ${TAILSCALE_EXIT_NODE} for Scaleway API calls"
  tailscale set --advertise-exit-node=false
  TAILSCALE_EGRESS_ACTIVE=1

  local allow_lan="false"
  if is_true "${TAILSCALE_ALLOW_LAN_ACCESS}"; then
    allow_lan="true"
  fi
  tailscale set --exit-node="${TAILSCALE_EXIT_NODE}" --exit-node-allow-lan-access="${allow_lan}"

  if have curl; then
    for _ in {1..10}; do
      if curl -4 -sS --connect-timeout 2 --max-time 5 -o /dev/null https://api.scaleway.com >/dev/null 2>&1; then
        return 0
      fi
      sleep 1
    done
    log "WARN: IPv4 check to api.scaleway.com did not pass yet; continuing and letting scw report the exact error"
  fi
}

restore_scaleway_egress() {
  if [[ "${TAILSCALE_EGRESS_ACTIVE}" -ne 1 ]]; then
    return 0
  fi

  TAILSCALE_EGRESS_ACTIVE=0
  log "Restoring Tailscale exit-node state"

  if [[ -n "${TAILSCALE_PREVIOUS_EXIT_NODE}" && "${TAILSCALE_PREVIOUS_EXIT_NODE}" != "0" ]]; then
    tailscale set --exit-node="${TAILSCALE_PREVIOUS_EXIT_NODE}" --exit-node-allow-lan-access="${TAILSCALE_PREVIOUS_ALLOW_LAN_ACCESS}" || true
    return 0
  fi

  tailscale set --exit-node= || true

  local restore_advertise=0
  case "${TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE,,}" in
    auto)
      [[ "${TAILSCALE_WAS_ADVERTISING_EXIT_NODE}" == "1" ]] && restore_advertise=1
      ;;
    true|1|yes|on)
      restore_advertise=1
      ;;
  esac

  if [[ "${restore_advertise}" -eq 1 ]]; then
    tailscale set --advertise-exit-node=true || true
  fi
}

scw_json() {
  local description="$1"
  shift

  local output
  if ! output="$("$@" -o json 2>&1)"; then
    printf '%s\n' "${output}" >&2
    die "Scaleway API call failed while ${description}. If this host is IPv6-only, provide IPv4 egress with a Tailscale exit node/NAT64 or run the Scaleway control-plane step from an IPv4-capable helper."
  fi

  if ! printf '%s\n' "${output}" | python3 -m json.tool >/dev/null 2>&1; then
    printf '%s\n' "${output}" >&2
    die "Scaleway API call returned non-JSON output while ${description}"
  fi

  printf '%s\n' "${output}"
}

metadata_value() {
  local key="$1"
  local metadata_json=""

  if have curl; then
    metadata_json="$(curl -g -6 -fsS --connect-timeout 1 --max-time 3 "http://[fd00:42::42]/conf?format=json" 2>/dev/null || true)"
    if [[ -z "${metadata_json}" ]]; then
      metadata_json="$(curl -4 -fsS --connect-timeout 1 --max-time 3 --local-port 1-1023 "http://169.254.42.42/conf?format=json" 2>/dev/null || true)"
    fi
  fi

  [[ -n "${metadata_json}" ]] || return 0
  printf '%s\n' "${metadata_json}" \
    | python3 -c 'import json, sys; data=json.load(sys.stdin); print(data.get(sys.argv[1], "") or "")' "${key}" 2>/dev/null || true
}

detect_server_id_and_zone() {
  if [[ -n "${SERVER_ID}" ]]; then
    return 0
  fi

  if have curl; then
    SERVER_ID="$(metadata_value ID)"
    local meta_zone
    meta_zone="$(metadata_value ZONE)"
    [[ -n "${meta_zone}" ]] && ZONE="${meta_zone}"
  fi

  if [[ -z "${SERVER_ID}" ]]; then
    local host_name
    local servers_json
    host_name="$(hostname)"
    servers_json="$(scw_json "listing instances in ${ZONE}" scw instance server list zone="${ZONE}")"
    SERVER_ID="$(
      printf '%s\n' "${servers_json}" | python3 -c '
import json
import sys

host = sys.argv[1]
short = host.split(".", 1)[0]
candidates = {host, short, host.lower(), short.lower()}

raw = json.load(sys.stdin)
if isinstance(raw, list):
    servers = raw
elif isinstance(raw, dict):
    servers = raw.get("servers") or raw.get("Servers") or raw.get("items") or []
else:
    servers = []

for server in servers:
    if not isinstance(server, dict):
        continue
    names = [
        str(server.get("name") or ""),
        str(server.get("hostname") or ""),
    ]
    if any(name in candidates or name.lower() in candidates for name in names if name):
        print(server.get("id", "") or "")
        raise SystemExit(0)

print("")
' "${host_name}"
    )"
    if [[ -z "${SERVER_ID}" ]]; then
      printf 'Could not match hostname %s to a Scaleway instance in zone %s. Instances visible there:\n' "${host_name}" "${ZONE}" >&2
      printf '%s\n' "${servers_json}" | python3 -c '
import json
import sys

raw = json.load(sys.stdin)
if isinstance(raw, list):
    servers = raw
elif isinstance(raw, dict):
    servers = raw.get("servers") or raw.get("Servers") or raw.get("items") or []
else:
    servers = []

for server in servers:
    if isinstance(server, dict):
        name = server.get("name", "<unnamed>")
        server_id = server.get("id", "<no-id>")
        print(f"  {name}  {server_id}", file=sys.stderr)
' || true
    fi
  fi

  [[ -n "${SERVER_ID}" ]] || die "could not determine Scaleway server id; pass --server-id or set DELUGE_BURST_SERVER_ID in ${CONFIG_FILE}"
}

state_quote() {
  printf '%q' "$1"
}

write_state() {
  local volume_id="$1"
  local device_path="$2"
  local volume_name="$3"
  local created_at
  created_at="$(date -Is)"

  install -d -m 700 "${BURST_STATE_DIR}"
  {
    printf 'VOL_ID=%s\n' "$(state_quote "${volume_id}")"
    printf 'ZONE=%s\n' "$(state_quote "${ZONE}")"
    printf 'SERVER_ID=%s\n' "$(state_quote "${SERVER_ID}")"
    printf 'DEVICE_PATH=%s\n' "$(state_quote "${device_path}")"
    printf 'VOLUME_NAME=%s\n' "$(state_quote "${volume_name}")"
    printf 'SIZE_GB=%s\n' "$(state_quote "${SIZE_GB}")"
    printf 'IOPS=%s\n' "$(state_quote "${IOPS}")"
    printf 'FS=%s\n' "$(state_quote "${FS}")"
    printf 'BURST_MOUNT=%s\n' "$(state_quote "${BURST_MOUNT}")"
    printf 'BURST_BIND_TARGET=%s\n' "$(state_quote "${BURST_BIND_TARGET}")"
    printf 'CREATED_AT=%s\n' "$(state_quote "${created_at}")"
  } > "${BURST_STATE_FILE}"
  chmod 600 "${BURST_STATE_FILE}"
}

load_state() {
  if [[ -f "${BURST_STATE_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${BURST_STATE_FILE}"
    [[ -n "${ZONE:-}" ]] || ZONE="${DEFAULT_ZONE}"
    [[ -n "${SERVER_ID:-}" ]] || SERVER_ID=""
  fi
}

remove_state() {
  rm -f "${BURST_STATE_FILE}"
}

is_active() {
  [[ -f "${BURST_STATE_FILE}" ]] || mountpoint -q "${BURST_MOUNT}" || mountpoint -q "${BURST_BIND_TARGET}"
}

ensure_not_active() {
  if is_active; then
    status
    die "burst storage already appears active"
  fi
}

ensure_base_dirs() {
  install -d -m 750 "${DOWNLOAD_DIR}" "${FINISHED_DIR}"
  chown "${DELUGE_USER_SYS}:${DELUGE_USER_SYS}" "${DOWNLOAD_DIR}" "${FINISHED_DIR}" 2>/dev/null || true
}

wait_for_device() {
  local volume_id="$1"
  local dev_path=""
  local by_id

  for _ in {1..90}; do
    for by_id in /dev/disk/by-id/*"volume-${volume_id}"* /dev/disk/by-id/*"${volume_id}"*; do
      if [[ -e "${by_id}" ]]; then
        dev_path="$(readlink -f "${by_id}")"
        [[ -b "${dev_path}" ]] && { printf '%s\n' "${dev_path}"; return 0; }
      fi
    done

    dev_path="$(
      lsblk -rno NAME,SERIAL,TYPE 2>/dev/null \
        | awk -v serial="volume-${volume_id}" '$2 == serial && $3 == "disk" { print "/dev/" $1; exit }'
    )"
    if [[ -n "${dev_path}" && -b "${dev_path}" ]]; then
      printf '%s\n' "${dev_path}"
      return 0
    fi
    sleep 1
  done

  return 1
}

ensure_filesystem() {
  local dev_path="$1"

  if blkid "${dev_path}" >/dev/null 2>&1; then
    return 0
  fi

  case "${FS}" in
    ext4)
      require_commands mkfs.ext4
      log "Creating ext4 filesystem on ${dev_path}"
      mkfs.ext4 -F "${dev_path}" >/dev/null
      ;;
    xfs)
      require_commands mkfs.xfs
      log "Creating xfs filesystem on ${dev_path}"
      mkfs.xfs -f "${dev_path}" >/dev/null
      ;;
  esac
}

update_deluge_paths() {
  local new_download="$1"
  local new_completed="$2"
  local restart_needed=0

  restart_deluge_on_return() {
    if [[ "${restart_needed}" -eq 1 ]]; then
      log "Restarting ${DELUGE_SERVICE} after an interrupted path update"
      systemctl start "${DELUGE_SERVICE}" || true
    fi
  }
  trap restart_deluge_on_return RETURN

  [[ -f "${DELUGE_CORE_CONF}" ]] || die "Deluge core config not found at ${DELUGE_CORE_CONF}"

  log "Stopping ${DELUGE_SERVICE} to update Deluge paths"
  systemctl stop "${DELUGE_SERVICE}"
  restart_needed=1

  local backup="${DELUGE_CORE_CONF}.burst.$(date +%Y%m%d_%H%M%S)"
  cp -a "${DELUGE_CORE_CONF}" "${backup}"

  python3 - "${DELUGE_CORE_CONF}" "${new_download}" "${new_completed}" <<'PY'
import json
import os
import sys
import tempfile

path, download_location, move_completed_path = sys.argv[1:4]
raw = open(path, "r", encoding="utf-8").read()
decoder = json.JSONDecoder()
header = {"file": 1, "format": 1}

try:
    first, idx = decoder.raw_decode(raw)
    while idx < len(raw) and raw[idx].isspace():
        idx += 1
    if idx < len(raw):
        second, _ = decoder.raw_decode(raw, idx)
        header = first if isinstance(first, dict) else header
        data = second
    else:
        data = first
except json.JSONDecodeError as exc:
    print(f"Invalid Deluge config {path}: {exc}", file=sys.stderr)
    sys.exit(1)

if not isinstance(data, dict):
    print(f"Deluge config {path} did not contain a JSON object.", file=sys.stderr)
    sys.exit(1)

data["download_location"] = download_location
data["move_completed"] = True
data["move_completed_path"] = move_completed_path

stat = os.stat(path)
directory = os.path.dirname(path) or "."
fd, tmp_path = tempfile.mkstemp(dir=directory)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(header, sort_keys=True))
    handle.write("\n")
    handle.write(json.dumps(data, sort_keys=True))
    handle.write("\n")
os.chmod(tmp_path, stat.st_mode & 0o777)
os.chown(tmp_path, stat.st_uid, stat.st_gid)
os.replace(tmp_path, path)
PY

  chown "${DELUGE_USER_SYS}:${DELUGE_USER_SYS}" "${DELUGE_CORE_CONF}" 2>/dev/null || true
  chmod 600 "${DELUGE_CORE_CONF}" 2>/dev/null || true

  log "Starting ${DELUGE_SERVICE}"
  systemctl start "${DELUGE_SERVICE}"
  restart_needed=0
  trap - RETURN
}

restore_base_paths() {
  ensure_base_dirs
  update_deluge_paths "${DOWNLOAD_DIR}" "${FINISHED_DIR}"
}

repair_active() {
  [[ -d "${BURST_MOUNT}" ]] || die "burst mount path ${BURST_MOUNT} does not exist"
  mountpoint -q "${BURST_MOUNT}" || die "${BURST_MOUNT} is not mounted"

  install -d -m 750 "${BURST_COMPLETED}" "${BURST_INCOMPLETE}" "${BURST_BIND_TARGET}"
  chown -R "${DELUGE_USER_SYS}:${DELUGE_USER_SYS}" "${BURST_MOUNT}" "${BURST_BIND_TARGET}" 2>/dev/null || true

  if ! mountpoint -q "${BURST_BIND_TARGET}"; then
    log "Binding completed burst downloads into ${BURST_BIND_TARGET}"
    mount --bind "${BURST_COMPLETED}" "${BURST_BIND_TARGET}"
  fi

  update_deluge_paths "${BURST_INCOMPLETE}" "${BURST_COMPLETED}"
  status
}

path_has_entries_other_than_markers() {
  local dir="$1"
  [[ -d "${dir}" ]] || return 1
  find "${dir}" -mindepth 1 \
    ! -name '.OVERFLOW_ACTIVE' \
    ! -name 'lost+found' \
    -print -quit | grep -q .
}

require_burst_empty() {
  local dir
  for dir in "${BURST_COMPLETED}" "${BURST_INCOMPLETE}"; do
    if path_has_entries_other_than_markers "${dir}"; then
      die "${dir} is not empty; rsync/import/remove its contents before teardown"
    fi
  done
}

find_volume_id_from_mount() {
  local source="$1"
  local real=""
  local serial=""
  local pkname=""

  [[ -n "${source}" ]] || return 1
  real="$(readlink -f "${source}" 2>/dev/null || true)"
  [[ -n "${real}" ]] || return 1

  serial="$(lsblk -no SERIAL "${real}" 2>/dev/null | head -n1 | tr -d '[:space:]' || true)"
  if [[ -z "${serial}" ]]; then
    pkname="$(lsblk -no PKNAME "${real}" 2>/dev/null | head -n1 | tr -d '[:space:]' || true)"
    if [[ -n "${pkname}" ]]; then
      serial="$(lsblk -no SERIAL "/dev/${pkname}" 2>/dev/null | head -n1 | tr -d '[:space:]' || true)"
    fi
  fi
  if [[ -z "${serial}" ]]; then
    serial="$(
      lsblk -rno NAME,SERIAL 2>/dev/null \
        | awk -v name="$(basename "${real}")" -v pk="${pkname}" '($1 == name || (pk != "" && $1 == pk)) { print $2; exit }'
    )"
  fi
  if [[ -z "${serial}" ]]; then
    serial="$(
      udevadm info --query=property --name="${real}" 2>/dev/null \
        | awk -F= '/^(ID_SERIAL|ID_SERIAL_SHORT)=/ { print $2; exit }'
    )"
  fi

  serial="${serial#volume-}"
  [[ -n "${serial}" ]] || return 1
  printf '%s\n' "${serial}"
}

provision() {
  require_commands scw python3 lsblk blkid mount mountpoint systemctl flock awk readlink
  ensure_not_active
  ensure_base_dirs
  enable_scaleway_egress
  detect_server_id_and_zone

  local volume_name="${NAME_PREFIX}-$(hostname)-$(date +%Y%m%d%H%M%S)"
  confirm_cost_action "Create a ${SIZE_GB}G Scaleway block volume in ${ZONE} for Deluge burst mode?"

  log "Creating ${SIZE_GB}G Scaleway volume ${volume_name} in ${ZONE} with ${IOPS} IOPS"
  local volume_json volume_id
  volume_json="$(scw_json "creating burst block volume" scw block volume create name="${volume_name}" from-empty.size="${SIZE_GB}G" perf-iops="${IOPS}" zone="${ZONE}")"
  volume_id="$(printf '%s\n' "${volume_json}" | python_json_value id)"
  [[ -n "${volume_id}" ]] || die "Scaleway did not return a volume id"

  log "Waiting for volume ${volume_id} to become available"
  scw block volume wait "${volume_id}" zone="${ZONE}" terminal-status=available >/dev/null

  log "Attaching volume ${volume_id} to server ${SERVER_ID}"
  scw instance server attach-volume server-id="${SERVER_ID}" volume-id="${volume_id}" volume-type=sbs_volume zone="${ZONE}" >/dev/null
  scw block volume wait "${volume_id}" zone="${ZONE}" terminal-status=in_use >/dev/null
  restore_scaleway_egress

  log "Resolving local block device for ${volume_id}"
  local dev_path
  dev_path="$(wait_for_device "${volume_id}")" || die "could not find local block device for volume ${volume_id}"
  log "Volume device is ${dev_path}"

  ensure_filesystem "${dev_path}"

  install -d -m 750 "${BURST_MOUNT}"
  log "Mounting ${dev_path} at ${BURST_MOUNT}"
  mountpoint -q "${BURST_MOUNT}" || mount -o noatime "${dev_path}" "${BURST_MOUNT}"

  install -d -m 750 "${BURST_COMPLETED}" "${BURST_INCOMPLETE}" "${BURST_BIND_TARGET}"
  chown -R "${DELUGE_USER_SYS}:${DELUGE_USER_SYS}" "${BURST_MOUNT}" "${BURST_BIND_TARGET}" 2>/dev/null || true

  log "Binding completed burst downloads into ${BURST_BIND_TARGET}"
  mountpoint -q "${BURST_BIND_TARGET}" || mount --bind "${BURST_COMPLETED}" "${BURST_BIND_TARGET}"
  chown "${DELUGE_USER_SYS}:${DELUGE_USER_SYS}" "${BURST_BIND_TARGET}" 2>/dev/null || true
  : > "${BURST_MARKER}"
  chown "${DELUGE_USER_SYS}:${DELUGE_USER_SYS}" "${BURST_MARKER}" 2>/dev/null || true

  update_deluge_paths "${BURST_INCOMPLETE}" "${BURST_COMPLETED}"
  write_state "${volume_id}" "${dev_path}" "${volume_name}"

  cat <<EOF

OK: Deluge burst mode is active.

Volume:      ${volume_id} (${SIZE_GB}G, ${IOPS} IOPS, ${ZONE})
Mounted at:  ${BURST_MOUNT}
Incomplete:  ${BURST_INCOMPLETE}
Completed:   ${BURST_COMPLETED}
Rsync path:  finished/_overflow -> ${BURST_COMPLETED}
State file:  ${BURST_STATE_FILE}
EOF
}

teardown() {
  require_commands scw python3 lsblk findmnt mountpoint umount systemctl awk readlink udevadm
  load_state

  local source_before=""
  source_before="$(findmnt -no SOURCE "${BURST_MOUNT}" 2>/dev/null || true)"
  if [[ -z "${VOL_ID:-}" && -n "${source_before}" ]]; then
    VOL_ID="$(find_volume_id_from_mount "${source_before}" || true)"
  fi

  [[ -n "${VOL_ID:-}" ]] || die "no burst volume id found; ${BURST_STATE_FILE} is missing and mount source was not identifiable"
  [[ -n "${ZONE:-}" ]] || ZONE="${DEFAULT_ZONE}"

  require_burst_empty
  confirm_cost_action "Delete burst volume ${VOL_ID} in ${ZONE}?"

  restore_base_paths

  log "Unbinding ${BURST_BIND_TARGET}"
  mountpoint -q "${BURST_BIND_TARGET}" && umount "${BURST_BIND_TARGET}" || true

  log "Unmounting ${BURST_MOUNT}"
  mountpoint -q "${BURST_MOUNT}" && umount "${BURST_MOUNT}" || true

  if [[ -z "${SERVER_ID:-}" ]]; then
    enable_scaleway_egress
    detect_server_id_and_zone
  else
    enable_scaleway_egress
  fi

  log "Detaching volume ${VOL_ID} from server ${SERVER_ID}"
  scw instance server detach-volume server-id="${SERVER_ID}" volume-id="${VOL_ID}" zone="${ZONE}" >/dev/null
  scw block volume wait "${VOL_ID}" zone="${ZONE}" terminal-status=available >/dev/null

  log "Deleting volume ${VOL_ID}"
  scw block volume delete "${VOL_ID}" zone="${ZONE}" >/dev/null
  restore_scaleway_egress

  rm -f "${BURST_MARKER}" 2>/dev/null || true
  rmdir "${BURST_BIND_TARGET}" 2>/dev/null || true
  rmdir "${BURST_MOUNT}" 2>/dev/null || true
  remove_state

  log "Teardown complete; Deluge is back on ${DOWNLOAD_DIR} -> ${FINISHED_DIR}"
}

deluge_core_value() {
  local key="$1"
  [[ -f "${DELUGE_CORE_CONF}" ]] || return 0
  python3 - "${DELUGE_CORE_CONF}" "${key}" <<'PY'
import json
import sys

path, key = sys.argv[1:3]
raw = open(path, "r", encoding="utf-8").read()
decoder = json.JSONDecoder()
try:
    first, idx = decoder.raw_decode(raw)
    while idx < len(raw) and raw[idx].isspace():
        idx += 1
    data = decoder.raw_decode(raw, idx)[0] if idx < len(raw) else first
except json.JSONDecodeError:
    data = {}
value = data.get(key, "") if isinstance(data, dict) else ""
print(value if value is not None else "")
PY
}

status() {
  load_state

  printf 'Burst state:       '
  if is_active; then
    printf 'active or partially active\n'
  else
    printf 'inactive\n'
  fi

  printf 'State file:        %s\n' "${BURST_STATE_FILE}"
  if [[ -f "${BURST_STATE_FILE}" ]]; then
    printf 'Volume:           %s\n' "${VOL_ID:-unknown}"
    printf 'Zone:             %s\n' "${ZONE:-unknown}"
    printf 'Created at:       %s\n' "${CREATED_AT:-unknown}"
  fi

  printf 'Mount active:      '
  mountpoint -q "${BURST_MOUNT}" && printf 'yes (%s)\n' "$(findmnt -no SOURCE "${BURST_MOUNT}" 2>/dev/null || true)" || printf 'no\n'

  printf 'Completed bind:    '
  mountpoint -q "${BURST_BIND_TARGET}" && printf 'yes\n' || printf 'no\n'

  printf 'Deluge download:   %s\n' "$(deluge_core_value download_location)"
  printf 'Deluge completed:  %s\n' "$(deluge_core_value move_completed_path)"

  if [[ -d "${BURST_MOUNT}" ]]; then
    df -h "${BURST_MOUNT}" 2>/dev/null || true
  fi
}

main() {
  load_config
  parse_args "$@"
  validate_args
  require_root
  acquire_lock
  trap restore_scaleway_egress EXIT

  case "${COMMAND}" in
    provision)
      provision
      ;;
    teardown)
      teardown
      ;;
    repair-active)
      repair_active
      ;;
    restore-base)
      restore_base_paths
      ;;
    status)
      status
      ;;
  esac
}

main "$@"
