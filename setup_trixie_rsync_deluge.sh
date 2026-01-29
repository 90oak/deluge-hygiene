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
DELUGE_STATE_DIR="/var/lib/deluged"
DELUGE_CONFIG_DIR="${DELUGE_STATE_DIR}/config"

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

  if ls "${plugin_dir}/ltConfig"*.egg >/dev/null 2>&1; then
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
ExecStart=/usr/bin/deluged -d -q -c /var/lib/deluged/config
DELUGED
  systemctl daemon-reload
}

wait_for_deluge() {
  local attempts=30
  while (( attempts > 0 )); do
    if auth_line=$(get_deluge_auth 2>/dev/null); then
      local deluge_user deluge_pass
      read -r deluge_user deluge_pass <<<"${auth_line}"
      if sudo -u debian-deluged deluge-console -c "${DELUGE_CONFIG_DIR}" \
        "connect 127.0.0.1:58846 ${deluge_user} ${deluge_pass}; info" \
        >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 1
    attempts=$((attempts - 1))
  done
  return 1
}

get_deluge_auth() {
  local auth_file="${DELUGE_CONFIG_DIR}/auth"
  if [[ ! -f "${auth_file}" ]]; then
    return 1
  fi

  local entry
  entry=$(awk -F: '$1 == "localclient" { print $1 ":" $2; exit }' "${auth_file}")
  if [[ -z "${entry}" ]]; then
    return 1
  fi

  local deluge_user deluge_pass
  IFS=: read -r deluge_user deluge_pass <<<"${entry}"
  if [[ -z "${deluge_user}" || -z "${deluge_pass}" ]]; then
    return 1
  fi

  printf '%s %s\n' "${deluge_user}" "${deluge_pass}"
}

deluge_console_cmd() {
  local cmd=$1
  local console_base=(sudo -u debian-deluged deluge-console -c "${DELUGE_CONFIG_DIR}")
  local stderr_file
  stderr_file=$(mktemp)

  if "${console_base[@]}" --help 2>&1 | grep -q -- "--command"; then
    "${console_base[@]}" --command "${cmd}" 2>"${stderr_file}"
  else
    "${console_base[@]}" "${cmd}" 2>"${stderr_file}"
  fi
  local exit_code=$?

  if [[ ${exit_code} -eq 0 ]]; then
    grep -v -E "AttributeError: 'ConsoleUI' object has no attribute 'started_deferred'|Unhandled error in Deferred|/usr/lib/python3/dist-packages/deluge/ui/console/main.py:367" "${stderr_file}" >&2 || true
  else
    cat "${stderr_file}" >&2
  fi
  rm -f "${stderr_file}"
  return "${exit_code}"
}

detect_global_ipv6() {
  local ipv6
  ipv6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1 | tr -d '[:space:]')
  if [[ -n ${ipv6} ]]; then
    if python3 - <<PY
import ipaddress
import sys
try:
    addr = ipaddress.IPv6Address("${ipv6}")
except ValueError:
    sys.exit(1)
if addr in ipaddress.IPv6Network("2000::/3"):
    sys.exit(0)
sys.exit(1)
PY
    then
      printf '%s\n' "${ipv6}"
      return 0
    fi
  fi

 ipv6=$(ip -6 addr show scope global | python3 -c '
import ipaddress, sys
lines = sys.stdin.read().splitlines()
preferred, temporary = [], []
for line in lines:
    line = line.strip()
    if not line.startswith("inet6 "):
        continue
    parts = line.split()
    ip = parts[1].split("/")[0]
    try:
        addr = ipaddress.IPv6Address(ip)
    except ValueError:
        continue
    if addr not in ipaddress.IPv6Network("2000::/3"):
        continue
    (temporary if "temporary" in parts else preferred).append(ip)

if preferred:
    print(preferred[0], end="")
elif temporary:
    print(temporary[0], end="")
'
)

  printf '%s\n' "${ipv6}"
}

detect_plugin_ids() {
  local plugin_dir="${DELUGE_CONFIG_DIR}/plugins"
  local egg_files=()
  local egg
  for egg in "${plugin_dir}"/*.egg; do
    if [[ -f ${egg} ]]; then
      egg_files+=("${egg}")
    fi
  done

  local plugin_info
  plugin_info=$(python3 - "${egg_files[@]}" <<'PY'
import configparser
import json
import os
import sys
import zipfile

eggs = sys.argv[1:]
result = {
    "label_id": "",
    "label_egg": "",
    "ltconfig_id": "",
    "ltconfig_egg": "",
}

def ids_from_egg(path):
    ids = []
    try:
        with zipfile.ZipFile(path) as zf:
            for candidate in ("EGG-INFO/entry_points.txt", "entry_points.txt"):
                if candidate in zf.namelist():
                    raw = zf.read(candidate).decode("utf-8")
                    parser = configparser.ConfigParser()
                    parser.optionxform = str
                    parser.read_string(raw)
                    if parser.has_section("deluge.plugin"):
                        ids.extend(parser.options("deluge.plugin"))
                    break
    except Exception:
        ids = []
    if not ids:
        base = os.path.basename(path)
        if base.lower().endswith(".egg"):
            base = base[:-4]
        ids = [base.split("-")[0]]
    return ids

def ids_from_dir(path):
    ids = []
    if not os.path.isdir(path):
        return ids
    for entry in os.listdir(path):
        if entry.startswith("__"):
            continue
        full = os.path.join(path, entry)
        if os.path.isdir(full):
            ids.append(entry)
        elif entry.lower().endswith(".egg"):
            ids.extend(ids_from_egg(full))
    return ids

for egg in eggs:
    for plugin_id in ids_from_egg(egg):
        lower_id = plugin_id.lower()
        if "label" in lower_id and not result["label_id"]:
            result["label_id"] = plugin_id
            result["label_egg"] = os.path.basename(egg)
        if "ltconfig" in lower_id and not result["ltconfig_id"]:
            result["ltconfig_id"] = plugin_id
            result["ltconfig_egg"] = os.path.basename(egg)

for plugin_dir in (
    "/usr/lib/python3/dist-packages/deluge/plugins",
    "/usr/share/deluge/plugins",
    "/usr/lib/deluge/plugins",
):
    for plugin_id in ids_from_dir(plugin_dir):
        lower_id = plugin_id.lower()
        if "label" in lower_id and not result["label_id"]:
            result["label_id"] = plugin_id
            result["label_egg"] = plugin_dir
        if "ltconfig" in lower_id and not result["ltconfig_id"]:
            result["ltconfig_id"] = plugin_id
            result["ltconfig_egg"] = plugin_dir

print(json.dumps(result))
PY
)

  local label_plugin_id ltconfig_plugin_id label_plugin_egg ltconfig_plugin_egg
  label_plugin_id=$(python3 - <<PY
import json
print(json.loads('''${plugin_info}''')["label_id"])
PY
)
  ltconfig_plugin_id=$(python3 - <<PY
import json
print(json.loads('''${plugin_info}''')["ltconfig_id"])
PY
)
  label_plugin_egg=$(python3 - <<PY
import json
print(json.loads('''${plugin_info}''')["label_egg"])
PY
)
  ltconfig_plugin_egg=$(python3 - <<PY
import json
print(json.loads('''${plugin_info}''')["ltconfig_egg"])
PY
)

  if [[ -z ${label_plugin_id} || -z ${ltconfig_plugin_id} ]]; then
    echo "Unable to detect Label or ltconfig plugin IDs from ${DELUGE_CONFIG_DIR}/plugins." >&2
    echo "Detected label plugin: ${label_plugin_id:-none} (${label_plugin_egg:-unknown}); ltconfig plugin: ${ltconfig_plugin_id:-none} (${ltconfig_plugin_egg:-unknown})." >&2
    exit 1
  fi

  echo "Detected Label plugin ID: ${label_plugin_id} (egg: ${label_plugin_egg})." >&2
  echo "Detected ltconfig plugin ID: ${ltconfig_plugin_id} (egg: ${ltconfig_plugin_egg})." >&2

  printf '%s %s %s %s\n' "${label_plugin_id}" "${label_plugin_egg}" "${ltconfig_plugin_id}" "${ltconfig_plugin_egg}"
}

update_json_atomic() {
  local path=$1
  local python_snippet=$2
  local uid_gid_mode=$3

  python3 - <<PY
import json
import os
import tempfile
import sys

path = "${path}"
raw = None
try:
    raw = open(path, "r", encoding="utf-8").read()
except FileNotFoundError:
    raw = None

header = None
data = None

if raw is not None:
    # Try normal JSON first
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Try Deluge "two JSON objects" format: {header}\n{body}
        dec = json.JSONDecoder()
        try:
            header, idx = dec.raw_decode(raw)
            while idx < len(raw) and raw[idx].isspace():
                idx += 1
            data, _ = dec.raw_decode(raw, idx)
        except json.JSONDecodeError as exc:
            print(f"Invalid JSON in {path}: {exc}", file=sys.stderr)
            sys.exit(1)

    stat = os.stat(path)
    mode = stat.st_mode & 0o777
    uid = stat.st_uid
    gid = stat.st_gid
else:
    data = {}
    uid = int("${uid_gid_mode%%:*}")
    gid = int("${uid_gid_mode#*:}")
    mode = 0o600

${python_snippet}

directory = os.path.dirname(path) or "."
fd, tmp_path = tempfile.mkstemp(dir=directory)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    if header is not None and isinstance(header, dict):
        handle.write(json.dumps(header, sort_keys=True))
        handle.write("\\n")
        handle.write(json.dumps(data, sort_keys=True))
        handle.write("\\n")
    else:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\\n")

os.chmod(tmp_path, mode)
os.chown(tmp_path, uid, gid)
os.replace(tmp_path, path)
PY
}
update_deluge_core_conf_atomic() {
  local path=$1
  local python_snippet=$2
  local uid_gid_mode=$3

  python3 - <<PY
import json
import os
import tempfile
import sys

path = "${path}"
raw = open(path, "r", encoding="utf-8").read()
decoder = json.JSONDecoder()
header = None
config = None

try:
    header, idx = decoder.raw_decode(raw)
    while idx < len(raw) and raw[idx].isspace():
        idx += 1
    config, _ = decoder.raw_decode(raw, idx)
except json.JSONDecodeError:
    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"Invalid core.conf format in {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    header = {"file": 1, "format": 1}

if not isinstance(header, dict) or not isinstance(config, dict):
    print(f"core.conf in {path} must contain JSON objects.", file=sys.stderr)
    sys.exit(1)
if "file" not in header or "format" not in header:
    header = {"file": 1, "format": 1}

stat = os.stat(path)
mode = stat.st_mode & 0o777
uid = stat.st_uid
gid = stat.st_gid

data = config

${python_snippet}

directory = os.path.dirname(path) or "."
fd, tmp_path = tempfile.mkstemp(dir=directory)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(header, sort_keys=True))
    handle.write("\\n")
    handle.write(json.dumps(data, sort_keys=True))
    handle.write("\\n")
os.chmod(tmp_path, mode)
os.chown(tmp_path, uid, gid)
os.replace(tmp_path, path)
PY
}

configure_deluge() {
  install -d -m 750 "${DELUGE_CONFIG_DIR}"
  chown -R debian-deluged:debian-deluged "${DELUGE_STATE_DIR}"

  local public_ipv6
  public_ipv6=$(detect_global_ipv6)
  if [[ -z ${public_ipv6} ]]; then
    echo "Unable to determine global IPv6 address." >&2
    exit 1
  fi
  echo "Detected Tailscale IPv4: ${TAILSCALE_IP}"
  echo "Detected PUBLIC IPv6 (non-Tailscale): ${public_ipv6}"

  systemctl enable --now deluged
  local core_conf="${DELUGE_CONFIG_DIR}/core.conf"
  local attempts=30
  while [[ ! -f ${core_conf} && ${attempts} -gt 0 ]]; do
    sleep 1
    attempts=$((attempts - 1))
  done
  if [[ ! -f ${core_conf} ]]; then
    echo "core.conf was not created by deluged at ${core_conf}." >&2
    exit 1
  fi
  systemctl stop deluged

  local label_plugin_id label_plugin_egg ltconfig_plugin_id ltconfig_plugin_egg
  read -r label_plugin_id label_plugin_egg ltconfig_plugin_id ltconfig_plugin_egg <<<"$(detect_plugin_ids)"

  local deluge_uid deluge_gid
  deluge_uid=$(id -u debian-deluged)
  deluge_gid=$(id -g debian-deluged)

  update_deluge_core_conf_atomic "${core_conf}" "
data['download_location'] = '${DOWNLOAD_DIR}'
data['move_completed'] = True
data['move_completed_path'] = '${FINISHED_DIR}'
data['allow_remote'] = False
data['rpc_listen_interface'] = '127.0.0.1'
data['rpc_listen_interface_ipv6'] = '::1'
data['listen_interface_ipv6'] = '${public_ipv6}'
if data.get('listen_interface') == '${TAILSCALE_IP}':
    data['listen_interface'] = ''
enabled = data.get('enabled_plugins', [])
if not isinstance(enabled, list):
    raise SystemExit('enabled_plugins is not a list in core.conf')
for plugin in ('${label_plugin_id}', '${ltconfig_plugin_id}'):
    if plugin not in enabled:
        enabled.append(plugin)
data['enabled_plugins'] = enabled
" "${deluge_uid}:${deluge_gid}"

  local ltconfig_conf
  ltconfig_conf=$(find "${DELUGE_CONFIG_DIR}" -maxdepth 1 -type f -iname '*ltconfig*' | sort | head -n1 || true)
  if [[ -z ${ltconfig_conf} ]]; then
    ltconfig_conf="${DELUGE_CONFIG_DIR}/ltconfig.conf"
  fi

  python3 - <<PY
import json
import os
import sys
import tempfile

config_path = "${ltconfig_conf}"
public_ipv6 = "${public_ipv6}"
core_conf_path = "${core_conf}"
uid = int("${deluge_uid}")
gid = int("${deluge_gid}")

def load_deluge_config(path):
    raw = open(path, "r", encoding="utf-8").read()
    decoder = json.JSONDecoder()
    header = None
    body = None
    try:
        header, idx = decoder.raw_decode(raw)
        while idx < len(raw) and raw[idx].isspace():
            idx += 1
        body, _ = decoder.raw_decode(raw, idx)
    except json.JSONDecodeError:
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"Invalid JSON in {path}: {exc}", file=sys.stderr)
            sys.exit(1)
        header = {"file": 1, "format": 1}
    if not isinstance(header, dict) or not isinstance(body, dict):
        print(f"Config file {path} must contain JSON objects.", file=sys.stderr)
        sys.exit(1)
    if "file" not in header or "format" not in header:
        header = {"file": 1, "format": 1}
    return header, body

def get_listen_port_range(path):
    if not os.path.exists(path):
        return "6881"
    _, core_body = load_deluge_config(path)
    listen_ports = core_body.get("listen_ports")
    if isinstance(listen_ports, list) and len(listen_ports) == 2:
        start, end = listen_ports
        if isinstance(start, int) and isinstance(end, int):
            return str(start) if start == end else f"{start}-{end}"
    if isinstance(listen_ports, int):
        return str(listen_ports)
    return "6881"

created = False
if os.path.exists(config_path):
    header, body = load_deluge_config(config_path)
    stat = os.stat(config_path)
    mode = stat.st_mode & 0o777
else:
    header = {"file": 1, "format": 1}
    body = {"apply_on_start": True, "settings": {}}
    mode = 0o600
    created = True

if not isinstance(body, dict):
    print(f"ltconfig config {config_path} did not contain a JSON object.", file=sys.stderr)
    sys.exit(1)

settings = body.get("settings")
if not isinstance(settings, dict):
    settings = {}
    body["settings"] = settings

port_range = get_listen_port_range(core_conf_path)
settings["listen_interfaces"] = f"[{public_ipv6}]:{port_range}"
settings["outgoing_interfaces"] = public_ipv6
settings["outgoing_interface"] = public_ipv6

directory = os.path.dirname(config_path) or "."
fd, tmp_path = tempfile.mkstemp(dir=directory)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(header, sort_keys=True))
    handle.write("\\n")
    handle.write(json.dumps(body, sort_keys=True))
    handle.write("\\n")
os.chmod(tmp_path, mode)
os.chown(tmp_path, uid, gid)
os.replace(tmp_path, config_path)
if created:
    print(f"ltconfig config created at {config_path}.")
else:
    print(f"ltconfig config updated at {config_path}.")
PY

  systemctl start deluged

  systemctl enable --now deluge-web
  sleep 2
  systemctl stop deluge-web

  if [[ -f "${DELUGE_CONFIG_DIR}/web.conf" ]]; then
  update_deluge_core_conf_atomic "${DELUGE_CONFIG_DIR}/web.conf" "
data['interface'] = '${TAILSCALE_IP}'
" "${deluge_uid}:${deluge_gid}"
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
