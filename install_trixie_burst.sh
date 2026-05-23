#!/usr/bin/env bash
# Install the Trixie Deluge burst controller and maintenance cron.

set -euo pipefail

INSTALL_CRON=1
CRON_USER="debian-deluged"
SHORTCUT_USER=""
TAILSCALE_EXIT_NODE=""
PROMPT_TAILSCALE_EXIT_NODE=0
TAILSCALE_ALLOW_LAN_ACCESS="true"
TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE="auto"
SERVER_ID=""
PROMPT_SERVER_ID=0
ZONE=""
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

usage() {
  cat <<USAGE
Usage: sudo $(basename "$0") [options]

Options:
  --shortcut-user <user>   Allow this SSH user to run deluge-burstctl with sudo -n.
  --cron-user <user>       User for remove_oversized_torrents cron (default: debian-deluged).
  --tailscale-exit-node <node>
                           Persist a Tailscale exit node for Scaleway API calls.
  --prompt-tailscale-exit-node
                           Prompt securely-ish at install time and write only /etc/default/deluge-burst.
  --tailscale-allow-lan-access <true|false>
                           Keep local access while using the exit node (default: true).
  --tailscale-restore-advertise-exit-node <auto|true|false>
                           Restore exit-node advertising after API calls (default: auto).
  --server-id <id>         Persist the Scaleway server ID for this Debian box.
  --prompt-server-id       Prompt at install time for the Scaleway server ID.
  --zone <zone>            Persist the Scaleway zone, for example nl-ams-1.
  --no-cron                Do not install /etc/cron.d/deluge-remove-oversized.
  -h, --help               Show this help.

After install, an iPhone Shortcut can use "Run Script over SSH" with:
  sudo -n /usr/local/sbin/deluge-burstctl provision --size-gb 600 --yes
  sudo -n /usr/local/sbin/deluge-burstctl teardown --yes
  sudo -n /usr/local/sbin/deluge-burstctl status
USAGE
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "must be run as root"
}

shell_quote() {
  printf '%q' "$1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shortcut-user)
      SHORTCUT_USER="${2:-}"
      shift 2
      ;;
    --cron-user)
      CRON_USER="${2:-}"
      shift 2
      ;;
    --tailscale-exit-node)
      TAILSCALE_EXIT_NODE="${2:-}"
      shift 2
      ;;
    --prompt-tailscale-exit-node)
      PROMPT_TAILSCALE_EXIT_NODE=1
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
    --server-id)
      SERVER_ID="${2:-}"
      shift 2
      ;;
    --prompt-server-id)
      PROMPT_SERVER_ID=1
      shift
      ;;
    --zone)
      ZONE="${2:-}"
      shift 2
      ;;
    --no-cron)
      INSTALL_CRON=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

require_root

[[ -f "${SOURCE_DIR}/deluge_burstctl.sh" ]] || die "missing ${SOURCE_DIR}/deluge_burstctl.sh"
[[ -f "${SOURCE_DIR}/remove_oversized_torrents.py" ]] || die "missing ${SOURCE_DIR}/remove_oversized_torrents.py"

if [[ "${PROMPT_TAILSCALE_EXIT_NODE}" -eq 1 ]]; then
  read -r -p "Tailscale exit node for Scaleway API egress (leave blank to skip): " TAILSCALE_EXIT_NODE
fi

if [[ "${PROMPT_SERVER_ID}" -eq 1 ]]; then
  read -r -p "Scaleway server ID for this Debian box (leave blank to auto-detect): " SERVER_ID
fi

case "${TAILSCALE_ALLOW_LAN_ACCESS,,}" in
  true|false|1|0|yes|no|on|off) ;;
  *) die "--tailscale-allow-lan-access must be true or false" ;;
esac

case "${TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE,,}" in
  auto|true|false|1|0|yes|no|on|off) ;;
  *) die "--tailscale-restore-advertise-exit-node must be auto, true, or false" ;;
esac

install -o root -g root -m 0755 "${SOURCE_DIR}/deluge_burstctl.sh" /usr/local/sbin/deluge-burstctl
install -o root -g root -m 0755 "${SOURCE_DIR}/remove_oversized_torrents.py" /usr/local/sbin/remove_oversized_torrents.py

echo "Installed /usr/local/sbin/deluge-burstctl"
echo "Installed /usr/local/sbin/remove_oversized_torrents.py"

if ! /usr/bin/python3 -c 'import deluge_client' >/dev/null 2>&1; then
  echo "WARN: /usr/bin/python3 cannot import deluge_client; the cleanup cron needs that package."
fi

if ! command -v scw >/dev/null 2>&1; then
  echo "WARN: scw was not found in PATH; burst provision/teardown need the Scaleway CLI."
fi

if [[ -n "${TAILSCALE_EXIT_NODE}" || -n "${SERVER_ID}" || -n "${ZONE}" ]]; then
  if [[ -n "${TAILSCALE_EXIT_NODE}" ]] && ! command -v tailscale >/dev/null 2>&1; then
    echo "WARN: tailscale was not found in PATH; configured exit-node support needs it."
  fi

  : > /etc/default/deluge-burst
  if [[ -n "${TAILSCALE_EXIT_NODE}" ]]; then
    {
      printf 'DELUGE_BURST_TAILSCALE_EXIT_NODE=%s\n' "$(shell_quote "${TAILSCALE_EXIT_NODE}")"
      printf 'DELUGE_BURST_TAILSCALE_ALLOW_LAN_ACCESS=%s\n' "$(shell_quote "${TAILSCALE_ALLOW_LAN_ACCESS}")"
      printf 'DELUGE_BURST_TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE=%s\n' "$(shell_quote "${TAILSCALE_RESTORE_ADVERTISE_EXIT_NODE}")"
    } >> /etc/default/deluge-burst
  fi
  if [[ -n "${SERVER_ID}" ]]; then
    printf 'DELUGE_BURST_SERVER_ID=%s\n' "$(shell_quote "${SERVER_ID}")" >> /etc/default/deluge-burst
  fi
  if [[ -n "${ZONE}" ]]; then
    printf 'DELUGE_BURST_ZONE=%s\n' "$(shell_quote "${ZONE}")" >> /etc/default/deluge-burst
  fi
  chmod 0644 /etc/default/deluge-burst
  echo "Installed /etc/default/deluge-burst"
fi

if [[ "${INSTALL_CRON}" -eq 1 ]]; then
  id "${CRON_USER}" >/dev/null 2>&1 || die "cron user ${CRON_USER} does not exist"
  cat > /etc/cron.d/deluge-remove-oversized <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

* * * * * ${CRON_USER} /usr/bin/python3 /usr/local/sbin/remove_oversized_torrents.py 2>&1 | /usr/bin/logger -t deluge-remove-oversized
EOF
  chmod 0644 /etc/cron.d/deluge-remove-oversized
  echo "Installed /etc/cron.d/deluge-remove-oversized"
fi

if [[ -n "${SHORTCUT_USER}" ]]; then
  id "${SHORTCUT_USER}" >/dev/null 2>&1 || die "shortcut user ${SHORTCUT_USER} does not exist"
  command -v visudo >/dev/null 2>&1 || die "visudo is required to install sudoers policy"

  sudoers_file="/etc/sudoers.d/deluge-burst-${SHORTCUT_USER}"
  cat > "${sudoers_file}" <<EOF
Cmnd_Alias DELUGE_BURSTCTL = /usr/local/sbin/deluge-burstctl provision *, /usr/local/sbin/deluge-burstctl teardown, /usr/local/sbin/deluge-burstctl teardown *, /usr/local/sbin/deluge-burstctl repair-active, /usr/local/sbin/deluge-burstctl restore-base, /usr/local/sbin/deluge-burstctl status
${SHORTCUT_USER} ALL=(root) NOPASSWD: DELUGE_BURSTCTL
EOF
  chmod 0440 "${sudoers_file}"
  visudo -cf "${sudoers_file}" >/dev/null
  echo "Installed ${sudoers_file}"
fi

cat <<'EOF'

Next checks on the Debian box:
  deluge-burstctl status
  python3 /usr/local/sbin/remove_oversized_torrents.py

Burst commands for an iPhone Shortcut over SSH:
  sudo -n /usr/local/sbin/deluge-burstctl provision --size-gb 600 --yes
  sudo -n /usr/local/sbin/deluge-burstctl teardown --yes
  sudo -n /usr/local/sbin/deluge-burstctl status
EOF
