#!/usr/bin/env bash
set -euo pipefail

IFACE="ens2"
PORT="6881"
DRY_RUN=0
VERIFY_ONLY=0
DELUGE_SERVICE="deluged"
DELUGEWEB_SERVICE="deluge-web"

usage() {
  cat <<USAGE
Usage: $0 [options]

Options:
  --iface <name>             Network interface (default: ens2)
  --port <port>              Deluge listen port (default: 6881)
  --deluge-service <name>    deluged systemd service name (default: deluged)
  --delugeweb-service <name> deluge-web systemd service name (default: deluge-web)
  --dry-run                  Print planned actions only, no changes
  --verify-only              Perform checks only, no changes
  -h, --help                 Show this help
USAGE
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

run_cmd() {
  local cmd="$*"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: $cmd"
    return 0
  fi
  eval "$cmd"
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
  fi
}

iface_exists() {
  ip link show dev "$IFACE" >/dev/null 2>&1
}

show_available_ifaces() {
  ip -br link
}

sysctl_get() {
  sysctl -n "$1" 2>/dev/null || true
}

print_before_state() {
  log "BEFORE: ip -6 addr show dev $IFACE"
  ip -6 addr show dev "$IFACE" || true
  log "BEFORE: ip -6 addr show dev $IFACE scope global"
  ip -6 addr show dev "$IFACE" scope global || true
  log "BEFORE: sysctl net.ipv6.conf.all.use_tempaddr=$(sysctl_get net.ipv6.conf.all.use_tempaddr)"
  log "BEFORE: sysctl net.ipv6.conf.default.use_tempaddr=$(sysctl_get net.ipv6.conf.default.use_tempaddr)"
  log "BEFORE: sysctl net.ipv6.conf.${IFACE}.use_tempaddr=$(sysctl_get net.ipv6.conf.${IFACE}.use_tempaddr)"
  log "BEFORE: Deluge listen state (ss -lnpt | egrep 'deluge|${PORT}')"
  ss -lnpt | grep -E "deluge|:${PORT}\\b" || true
}

persist_sysctl() {
  local sysctl_file="/etc/sysctl.d/99-ipv6-privacy.conf"
  local content="net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.${IFACE}.use_tempaddr = 2"

  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: write $sysctl_file with:"
    printf '%s\n' "$content"
    return 0
  fi

  printf '%s\n' "$content" > "$sysctl_file"
}

apply_ipv6_privacy() {
  log "Applying IPv6 privacy sysctl settings"
  run_cmd "sysctl -w net.ipv6.conf.all.use_tempaddr=2"
  run_cmd "sysctl -w net.ipv6.conf.default.use_tempaddr=2"
  run_cmd "sysctl -w net.ipv6.conf.${IFACE}.use_tempaddr=2"
  persist_sysctl
  run_cmd "sysctl --system"
}

flush_and_reconfigure_iface() {
  log "Flushing global IPv6 addresses on $IFACE"
  run_cmd "ip -6 addr flush dev ${IFACE} scope global"

  if command -v networkctl >/dev/null 2>&1; then
    log "Reconfiguring interface with networkctl"
    run_cmd "networkctl reconfigure ${IFACE}"
  else
    log "networkctl not available; bouncing link"
    run_cmd "ip link set ${IFACE} down"
    run_cmd "ip link set ${IFACE} up"
  fi
}

get_global_ipv6_addrs() {
  ip -6 addr show dev "$IFACE" scope global | awk '/inet6/ {print $2}' | cut -d/ -f1
}

check_global_ipv6_no_fffe() {
  local addrs
  addrs=$(get_global_ipv6_addrs)

  if [[ -z "$addrs" ]]; then
    return 2
  fi

  if echo "$addrs" | grep -qi 'ff:fe'; then
    return 1
  fi
  return 0
}

wait_for_global_ipv6() {
  local elapsed=0
  local timeout=20
  local interval=2

  while [[ $elapsed -lt $timeout ]]; do
    if check_global_ipv6_no_fffe; then
      return 0
    fi
    sleep "$interval"
    elapsed=$((elapsed + interval))
  done
  return 1
}

restart_deluge_services() {
  log "Restarting $DELUGE_SERVICE"
  run_cmd "systemctl restart ${DELUGE_SERVICE}"

  if systemctl list-unit-files --type=service | awk '{print $1}' | grep -qx "${DELUGEWEB_SERVICE}.service"; then
    log "Restarting $DELUGEWEB_SERVICE"
    run_cmd "systemctl restart ${DELUGEWEB_SERVICE}"
  else
    log "Deluge-web service ${DELUGEWEB_SERVICE} not found; skipping"
  fi
}

check_deluge_listen() {
  local ss_output
  ss_output=$(ss -lnpt | grep -E ":${PORT}\\b" || true)

  local ipv6_ok=0
  local ipv4_ok=0

  if echo "$ss_output" | grep -E -q "(\[::\]|:::):${PORT}\\b"; then
    ipv6_ok=1
  fi

  if echo "$ss_output" | grep -E -q "(0\.0\.0\.0|127\.0\.0\.1):${PORT}\\b"; then
    ipv4_ok=1
  fi

  if [[ $ipv4_ok -eq 1 && $ipv6_ok -eq 1 ]]; then
    return 0
  fi
  return 1
}

print_after_summary() {
  local sys_all sys_def sys_iface
  sys_all=$(sysctl_get net.ipv6.conf.all.use_tempaddr)
  sys_def=$(sysctl_get net.ipv6.conf.default.use_tempaddr)
  sys_iface=$(sysctl_get net.ipv6.conf.${IFACE}.use_tempaddr)

  log "AFTER: Global IPv6 addresses on ${IFACE}"
  get_global_ipv6_addrs || true

  if check_global_ipv6_no_fffe; then
    log "PASS: no global IPv6 addresses contain ff:fe"
  else
    log "FAIL: global IPv6 address contains ff:fe or missing"
  fi

  log "AFTER: sysctl net.ipv6.conf.all.use_tempaddr=${sys_all}"
  log "AFTER: sysctl net.ipv6.conf.default.use_tempaddr=${sys_def}"
  log "AFTER: sysctl net.ipv6.conf.${IFACE}.use_tempaddr=${sys_iface}"

  if check_deluge_listen; then
    log "PASS: Deluge listening on IPv4 and IPv6"
  else
    log "FAIL: Deluge not listening on IPv4 and IPv6"
  fi
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --iface)
        IFACE="$2"
        shift 2
        ;;
      --port)
        PORT="$2"
        shift 2
        ;;
      --deluge-service)
        DELUGE_SERVICE="$2"
        shift 2
        ;;
      --delugeweb-service)
        DELUGEWEB_SERVICE="$2"
        shift 2
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --verify-only)
        VERIFY_ONLY=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done

  require_root

  if ! iface_exists; then
    echo "ERROR: Interface ${IFACE} not found." >&2
    log "Available interfaces:"
    show_available_ifaces
    exit 1
  fi

  if [[ $DRY_RUN -eq 1 && $VERIFY_ONLY -eq 1 ]]; then
    echo "ERROR: --dry-run and --verify-only cannot be used together." >&2
    exit 1
  fi

  print_before_state

  if [[ $VERIFY_ONLY -eq 1 ]]; then
    local local_verify_status=0
    if ! check_global_ipv6_no_fffe; then
      log "FAIL: global IPv6 addresses missing or contain ff:fe"
      ip -6 addr show dev "$IFACE" scope global || true
      local_verify_status=1
    else
      log "PASS: global IPv6 addresses present and no ff:fe"
    fi

    if ! check_deluge_listen; then
      log "FAIL: Deluge not listening on both IPv4 and IPv6 on port ${PORT}"
      log "Guidance: In Deluge/ltConfig set listen_interfaces to 0.0.0.0:${PORT},[::]:${PORT} (comma-separated)."
      local_verify_status=1
    else
      log "PASS: Deluge listening on IPv4 and IPv6"
    fi

    print_after_summary
    exit "$local_verify_status"
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    log "Planned actions:"
    log "- Set sysctl net.ipv6.conf.all.use_tempaddr=2"
    log "- Set sysctl net.ipv6.conf.default.use_tempaddr=2"
    log "- Set sysctl net.ipv6.conf.${IFACE}.use_tempaddr=2"
    log "- Persist to /etc/sysctl.d/99-ipv6-privacy.conf"
    log "- Apply sysctl settings"
    log "- Flush global IPv6 on ${IFACE}"
    log "- Reconfigure ${IFACE} with networkctl or link bounce"
    log "- Wait for global IPv6 without ff:fe"
    log "- Restart ${DELUGE_SERVICE} (and ${DELUGEWEB_SERVICE} if present)"
    log "- Verify Deluge listens on IPv4+IPv6"
  fi

  apply_ipv6_privacy
  flush_and_reconfigure_iface

  if ! wait_for_global_ipv6; then
    log "ERROR: Timed out waiting for global IPv6 without ff:fe"
    ip -6 addr show dev "$IFACE" || true
    exit 1
  fi

  restart_deluge_services

  if ! check_deluge_listen; then
    log "ERROR: Deluge not listening on both IPv4 and IPv6 on port ${PORT}"
    log "Guidance: In Deluge/ltConfig set listen_interfaces to 0.0.0.0:${PORT},[::]:${PORT} (comma-separated)."
    print_after_summary
    exit 1
  fi

  print_after_summary
  log "SUCCESS: IPv6 privacy addresses active and Deluge listening on IPv4+IPv6"
}

main "$@"
