#!/usr/bin/env bash
# Тестовая обвязка: та же среда, что в install.sh (set -Eeuo pipefail + ERR→die), затем lib/ops.sh.
set -Eeuo pipefail
STATE=${STATE:-/root/vpn-setup}
PORT_REALITY=${PORT_REALITY:-443}; PORT_SUDOKU=${PORT_SUDOKU:-8443}; PORT_XHTTP=${PORT_XHTTP:-8080}
ARCH=${ARCH:-amd64}
XRAY_BIN=${XRAY_BIN:-${XUI_DIR:-/usr/local/x-ui}/bin/xray-linux-$ARCH}
c_ok='\033[1;32m'; c_err='\033[1;31m'; c_warn='\033[1;33m'; c_no='\033[0m'
step(){ echo -e "\n${c_ok}==> $*${c_no}"; }
warn(){ echo -e "${c_warn}! $*${c_no}"; }
die(){ echo -e "\n${c_err}ОШИБКА: $*${c_no}" >&2; exit 1; }
trap 'die "строка $LINENO: команда завершилась с ошибкой: $BASH_COMMAND"' ERR
ask(){ :; }
# shellcheck source=../../lib/ops.sh
. "$(dirname "$0")/../../lib/ops.sh"
if [ "${DEFINE_FW:-}" = 1 ]; then
  firewall_remove_ports(){ echo "firewall_remove_ports $*" >> "${CALLS_LOG:?}"; }
fi
cmd=${1:-help}; shift || true
case "$cmd" in
  status) ops_status "$@" || exit 1;;
  backup) ops_backup "$@";;
  links) ops_links "$@";;
  uninstall) ops_uninstall;;
  cron) ops_install_backup_cron;;
  uncron) ops_remove_backup_cron;;
  help) ops_help;;
  *) echo "unknown $cmd"; exit 2;;
esac
