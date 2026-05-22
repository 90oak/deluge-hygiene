#!/usr/bin/env bash
# Install the Trixie Deluge burst controller and maintenance cron.

set -euo pipefail

INSTALL_CRON=1
CRON_USER="debian-deluged"
SHORTCUT_USER=""
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

usage() {
  cat <<USAGE
Usage: sudo $(basename "$0") [options]

Options:
  --shortcut-user <user>   Allow this SSH user to run deluge-burstctl with sudo -n.
  --cron-user <user>       User for remove_oversized_torrents cron (default: debian-deluged).
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
Cmnd_Alias DELUGE_BURSTCTL = /usr/local/sbin/deluge-burstctl provision *, /usr/local/sbin/deluge-burstctl teardown, /usr/local/sbin/deluge-burstctl teardown *, /usr/local/sbin/deluge-burstctl restore-base, /usr/local/sbin/deluge-burstctl status
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
