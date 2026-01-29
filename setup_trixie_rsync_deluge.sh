#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root." >&2
  exit 1
fi

read -r -p "Enter the allowed IPv4 address for rsync access to Finished/Books: " ALLOWED_IP
if [[ -z ${ALLOWED_IP} ]]; then
  echo "Allowed IP cannot be empty." >&2
  exit 1
fi

if ! command -v tailscale >/dev/null 2>&1; then
  echo "tailscale is required but not installed or not in PATH." >&2
  exit 1
fi

TAILSCALE_IP=$(tailscale ip -4 | head -n1 | tr -d '[:space:]')
if [[ -z ${TAILSCALE_IP} ]]; then
  echo "Unable to determine Tailscale IPv4 address." >&2
  exit 1
fi

BASE_DIR="/srv/deluge"
DOWNLOAD_DIR="${BASE_DIR}/Downloads"
FINISHED_DIR="${BASE_DIR}/Finished"
BOOKS_DIR="${BASE_DIR}/Books"
DELUGE_CONFIG_DIR="/var/lib/deluge/.config/deluge"

configure_lean_apt() {
  cat > /etc/apt/apt.conf.d/99lean <<'APTCONF'
APT::Install-Recommends "0";
APT::Install-Suggests "0";
DPkg::Options {
   "--force-confdef";
   "--force-confold";
};
APTCONF

  cat > /etc/dpkg/dpkg.cfg.d/01lean <<'DPKGCONF'
path-exclude=/usr/share/doc/*
path-exclude=/usr/share/man/*
path-exclude=/usr/share/locale/*
path-exclude=/usr/share/info/*
DPKGCONF
}

install_packages() {
  apt-get update
  apt-get install -y --no-install-recommends \
    deluged \
    deluge-web \
    deluge-console \
    rsync

  if ! apt-get install -y --no-install-recommends deluge-ltconfig; then
    echo "deluge-ltconfig package not available; will build plugin from source." >&2
  fi
}

ensure_ltconfig_plugin() {
  local plugin_dir="${DELUGE_CONFIG_DIR}/plugins"

  if ls "${plugin_dir}/ltconfig"*.egg >/dev/null 2>&1; then
    return 0
  fi

  echo "ltconfig plugin not found; building from source." >&2
  apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 \
    python3-setuptools \
    unzip \
    wget

  local tmp_dir
  tmp_dir=$(mktemp -d)
  (
    cd "${tmp_dir}"
    wget -O ltconfig.zip \
      "https://github.com/ratanakvlun/deluge-ltconfig/archive/refs/tags/v2.0.0.zip"
    unzip -q ltconfig.zip
    cd deluge-ltconfig-2.0.0
    SETUPTOOLS_USE_DISTUTILS=local python3 setup.py bdist_egg
    install -d -m 755 "${plugin_dir}"
    install -m 644 dist/*.egg "${plugin_dir}/"
  )
  chown debian-deluged:debian-deluged "${plugin_dir}"/ltConfig*.egg
  rm -rf "${tmp_dir}"
}

setup_directories() {
  install -d -m 750 "${DOWNLOAD_DIR}" "${FINISHED_DIR}" "${BOOKS_DIR}"
  chown -R debian-deluged:debian-deluged "${BASE_DIR}"
}

enable_rsync_daemon() {
  cat > /etc/default/rsync <<'RSYNCDEFAULT'
RSYNC_ENABLE=true
RSYNCDEFAULT

  cat > /etc/rsyncd.conf <<RSYNCCONF
uid = debian-deluged
gid = debian-deluged
use chroot = yes
read only = yes
max connections = 4
pid file = /run/rsyncd.pid
lock file = /run/rsync.lock
log file = /var/log/rsyncd.log
address = ${TAILSCALE_IP}

[finished]
    path = ${FINISHED_DIR}
    comment = Finished torrents
    hosts allow = ${ALLOWED_IP}
    hosts deny = *

[books]
    path = ${BOOKS_DIR}
    comment = Books torrents
    hosts allow = ${ALLOWED_IP}
    hosts deny = *
RSYNCCONF
}

configure_journald() {
  install -d /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/99-limit.conf <<'JCONF'
[Journal]
SystemMaxFileSize=1M
JCONF
  systemctl restart systemd-journald
}

configure_btmp_rotation() {
  cat > /etc/logrotate.d/btmp <<'BTMP'
/var/log/btmp {
    missingok
    monthly
    create 0600 root utmp
    rotate 1
    size 1M
}
BTMP
}

configure_deluge_quiet() {
  install -d /etc/systemd/system/deluged.service.d
  cat > /etc/systemd/system/deluged.service.d/override.conf <<'DELUGED'
[Service]
ExecStart=
ExecStart=/usr/bin/deluged -d -q -c /var/lib/deluge/.config/deluge
DELUGED
  systemctl daemon-reload
}

wait_for_deluge() {
  local attempts=30
  while (( attempts > 0 )); do
    if sudo -u debian-deluged deluge-console -c "${DELUGE_CONFIG_DIR}" info >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    attempts=$((attempts - 1))
  done
  return 1
}

deluge_console_cmd() {
  local cmd=$1
  local console_base=(sudo -u debian-deluged deluge-console -c "${DELUGE_CONFIG_DIR}")

  if "${console_base[@]}" --help 2>&1 | grep -q -- "--command"; then
    "${console_base[@]}" --command "${cmd}"
  else
    "${console_base[@]}" "${cmd}"
  fi
}

wait_for_plugin() {
  local plugin_name=$1
  local attempts=15

  while (( attempts > 0 )); do
    if deluge_console_cmd "connect 127.0.0.1:58846; plugin -l" | grep -q "${plugin_name}"; then
      return 0
    fi
    sleep 1
    attempts=$((attempts - 1))
  done

  return 1
}

configure_deluge() {
  install -d -m 750 "${DELUGE_CONFIG_DIR}"
  chown -R debian-deluged:debian-deluged /var/lib/deluge

  systemctl enable --now deluged

  if ! wait_for_deluge; then
    echo "deluged did not become ready." >&2
    exit 1
  fi

  local base_config_cmd
  base_config_cmd="connect 127.0.0.1:58846; \
    config -s download_location \"${DOWNLOAD_DIR}\"; \
    config -s move_completed true; \
    config -s move_completed_path \"${FINISHED_DIR}\"; \
    config -s listen_interface \"${TAILSCALE_IP}\"; \
    plugin -e Label; \
    plugin -e ltconfig"

  if deluge_console_cmd "connect 127.0.0.1:58846; config -l" | grep -q "^listen_interface_ipv6"; then
    base_config_cmd="${base_config_cmd}; config -s listen_interface_ipv6 \"\""
  fi

  deluge_console_cmd "${base_config_cmd}"

  if ! wait_for_plugin "Label"; then
    echo "Label plugin did not become available." >&2
    exit 1
  fi

  deluge_console_cmd "connect 127.0.0.1:58846; \
    label add books; \
    label set books move_completed True; \
    label set books move_completed_path \"${BOOKS_DIR}\""

  systemctl restart deluged

  systemctl enable --now deluge-web
  sleep 2
  systemctl stop deluge-web

  if [[ -f "${DELUGE_CONFIG_DIR}/web.conf" ]]; then
    python3 - <<PY
import json
from pathlib import Path
path = Path("${DELUGE_CONFIG_DIR}/web.conf")
with path.open() as f:
    data = json.load(f)
data["interface"] = "${TAILSCALE_IP}"
with path.open("w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
PY
  else
    echo "deluge-web configuration not found at ${DELUGE_CONFIG_DIR}/web.conf" >&2
    exit 1
  fi

  systemctl start deluge-web
}

remove_unneeded_packages() {
  apt-get autoremove --purge -y
  apt-get clean
}

disable_unwanted_listeners() {
  local allowed_programs=("sshd" "deluged" "deluge-web" "rsync" "tailscaled")
  local allowed_units=("ssh.service" "deluged.service" "deluge-web.service" "rsync.service" "tailscaled.service")

  while read -r line; do
    local local_addr pid program unit
    local_addr=$(awk '{print $5}' <<<"${line}")
    pid=$(awk -F"pid=" '{print $2}' <<<"${line}" | awk -F"," '{print $1}')
    program=$(awk -F"users:\(\(" '{print $2}' <<<"${line}" | awk -F"," '{print $1}' | tr -d '"')

    if [[ -z ${pid} ]]; then
      continue
    fi

    if [[ ${local_addr} == 127.0.0.1:* || ${local_addr} == [::1]:* || ${local_addr} == ${TAILSCALE_IP}:* ]]; then
      continue
    fi

    if [[ ${program} == "sshd" || ${program} == "tailscaled" ]]; then
      continue
    fi

    unit=$(systemctl show -p Unit --value --pid="${pid}" 2>/dev/null || true)
    if [[ -n ${unit} ]]; then
      if [[ " ${allowed_units[*]} " == *" ${unit} "* ]]; then
        continue
      fi
      systemctl stop "${unit}" || true
      systemctl disable "${unit}" || true
    fi
  done < <(ss -tulpnH)
}

configure_lean_apt
install_packages
ensure_ltconfig_plugin
setup_directories
configure_journald
configure_btmp_rotation
configure_deluge_quiet
configure_deluge
enable_rsync_daemon
systemctl enable --now rsync
remove_unneeded_packages
disable_unwanted_listeners

echo "Setup complete. Tailscale IP: ${TAILSCALE_IP}. Rsync access allowed from ${ALLOWED_IP}."
