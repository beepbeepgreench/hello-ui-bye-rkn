#!/usr/bin/env bash
# shellcheck disable=SC2034  # переменные читаются внутри eval в check()
# Тесты lib/ssh.sh в песочнице: systemctl/ufw/fail2ban-client/journalctl/ss/who — заглушки (stubs/),
# sshd — обёртка над настоящим /usr/sbin/sshd с временным конфигом. Реальные /etc не меняются.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd); MOD="$ROOT/lib/ssh.sh"
PASS=0; FAIL=0; FAILED=()
ETC_SUMS=$(sha256sum /etc/ssh/sshd_config /etc/default/ufw /root/.ssh/authorized_keys 2>/dev/null)
RUNSSHD_EXISTED=0; [ -d /run/sshd ] && RUNSSHD_EXISTED=1
cleanup(){ if [ "$RUNSSHD_EXISTED" = 1 ]; then install -d -m 755 /run/sshd; fi; }
trap cleanup EXIT

new_env(){ # свежая песочница: $T
  T=$(mktemp -d); mkdir -p "$T/stub" "$T/sshd_config.d" "$T/root/.ssh" "$T/f2b/jail.d"
  : > "$T/log"; printf 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\n' > "$T/ufw"
  printf 'Include %s/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\n' "$T" > "$T/sshd_config"
  export STUB_DIR="$T/stub" STUB_LOG="$T/log" SSHD_CONFIG="$T/sshd_config" SSHD_DROPIN_DIR="$T/sshd_config.d" \
    SSH_AUTHKEYS="$T/root/.ssh/authorized_keys" SSH_AUTH_LOG="$T/auth.log" UFW_DEFAULTS_FILE="$T/ufw" \
    F2B_JAIL_FILE="$T/f2b/jail.d/sshd-vpn-setup.local" F2B_WAIT=5 PATH="$HERE/stubs:$PATH"
  unset SSH_CONNECTION SSH_CLIENT
}
# запуск функции модуля в среде install.sh: set -Eeuo pipefail + ERR trap → die
mod(){
  ( set -Eeuo pipefail
    c_ok=""; c_err=""; c_warn=""; c_no=""
    step(){ echo "STEP $*"; }; warn(){ echo "WARN $*"; }; die(){ echo "DIE $*"; exit 1; }
    ask(){ :; }
    trap 'die "ERR-TRAP line $LINENO: $BASH_COMMAND"' ERR
    # shellcheck source=/dev/null
    source "$MOD"
    "$@" ) 2>&1
}
ok(){ PASS=$((PASS+1)); echo "PASS  $1"; }
bad(){ FAIL=$((FAIL+1)); FAILED+=("$1"); echo "FAIL  $1"; echo "      out: ${OUT//$'\n'/ | }"; }
check(){ local name="$1"; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }
has(){ grep -qF -- "$2" <<<"$1"; }
inlog(){ grep -qF -- "$1" "$T/log"; }

# ---------------- detect_ssh_ports ----------------
new_env
rmdir /run/sshd 2>/dev/null || true
/usr/sbin/sshd -T -f "$SSHD_CONFIG" >/dev/null 2>&1; PRE=$?
OUT=$(mod detect_ssh_ports); RC=$?
check "detect: без /run/sshd (sshd -T до фикса rc=$PRE) → /run/sshd создан, sshd -T rc=0, вывод 22" \
  eval '[ "$RC" = 0 ] && [ -d /run/sshd ] && [ "$OUT" = 22 ] && inlog "rc=0" && [ "$PRE" != 0 ]'

new_env; echo 'Port 2200' >> "$SSHD_CONFIG"
OUT=$(PATH="$HERE/stubs-sshd-fail:$PATH" mod detect_ssh_ports); RC=$?
check "detect: sshd -T падает → не прерывается, берёт Port из sshd_config (2200)" eval '[ "$RC" = 0 ] && [ "$OUT" = 2200 ] && inlog "sshd(fail) -T"'

new_env; echo 'Port 22' >> "$SSHD_CONFIG"
OUT=$(SSH_CONNECTION="203.0.113.5 50000 198.51.100.1 2222" mod detect_ssh_ports); RC=$?
check "detect: SSH_CONNECTION порт 2222 + sshd_config 22 → '22 2222'" eval '[ "$RC" = 0 ] && [ "$OUT" = "22 2222" ]'

new_env; touch "$STUB_DIR/active_ssh.socket"; printf '[::]:2022 (Stream)\n0.0.0.0:2022 (Stream)\n' > "$STUB_DIR/listen_ssh.socket"
OUT=$(mod detect_ssh_ports)
check "detect: ssh.socket ListenStream 2022 (активен) → 2022 включён" eval 'has "$OUT" 2022'
rm "$STUB_DIR/active_ssh.socket"; OUT=$(mod detect_ssh_ports)
check "detect: ssh.socket неактивен/выключен → его Listen игнорируется" eval '! has "$OUT" 2022 && [ "$OUT" = 22 ]'

new_env
cat > "$STUB_DIR/ss_listen" <<'X'
LISTEN 0 128 0.0.0.0:5022 0.0.0.0:* users:(("sshd",pid=10,fd=3),("systemd",pid=1,fd=50))
LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray-linux-amd6",pid=286,fd=8))
LISTEN 0 4096 [::]:7000 [::]:* users:(("systemd",pid=1,fd=44))
X
echo '0 0 198.51.100.1:6022 203.0.113.5:51000 users:(("sshd-session",pid=99,fd=4))' > "$STUB_DIR/ss_est"
OUT=$(PATH="$HERE/stubs-sshd-fail:$PATH" mod detect_ssh_ports)
check "detect: ss — sshd 5022 и уст. сессия sshd-session 6022 да; xray 443 и чужой systemd 7000 нет" eval '[ "$OUT" = "5022 6022" ]'

new_env; OUT=$(PATH="$HERE/stubs-sshd-fail:$PATH" mod detect_ssh_ports); RC=$?
check "detect: ничего не найдено → запасной 22, rc=0" eval '[ "$RC" = 0 ] && [ "$OUT" = 22 ]'

new_env; echo 'ListenAddress 0.0.0.0:2345' >> "$SSHD_CONFIG"; OUT=$(mod detect_ssh_ports)
check "detect: ListenAddress host:port (sshd -T) → 2345" eval 'has "$OUT" 2345'

# ---------------- ssh_client_ip ----------------
new_env
OUT=$(SSH_CONNECTION="203.0.113.5 50000 198.51.100.1 22" mod ssh_client_ip); check "client_ip: из SSH_CONNECTION" eval '[ "$OUT" = 203.0.113.5 ]'
echo 'root pts/0 2026-10-31 17:00 (192.0.2.7)' > "$STUB_DIR/who"
OUT=$(mod ssh_client_ip); check "client_ip: из who am i (под sudo)" eval '[ "$OUT" = 192.0.2.7 ]'
echo 'root tty1 2026-10-31 17:00 (:0)' > "$STUB_DIR/who"
OUT=$(mod ssh_client_ip); RC=$?; check "client_ip: '(:0)' и нет SSH → пусто, rc=0" eval '[ -z "$OUT" ] && [ "$RC" = 0 ]'
OUT=$(SSH_CLIENT="2001:db8::5 5000 22" mod ssh_client_ip); check "client_ip: IPv6 из SSH_CLIENT" eval '[ "$OUT" = 2001:db8::5 ]'

# ---------------- firewall ----------------
new_env; echo 'Port 22' >> "$SSHD_CONFIG"; echo '80/tcp mine' > "$STUB_DIR/ufw_rules"
OUT=$(SSH_CONNECTION="203.0.113.5 50000 198.51.100.1 2222" mod firewall_apply 443 8443); RC=$?
R=$(cat "$STUB_DIR/ufw_rules")
check "firewall: разрешены 22+2222 (ssh), 443+8443 (vpn-setup), чужое правило 80 сохранено, enable вызван" \
  eval '[ "$RC" = 0 ] && has "$R" "22/tcp ssh" && has "$R" "2222/tcp ssh" && has "$R" "443/tcp vpn-setup" && has "$R" "8443/tcp vpn-setup" && has "$R" "80/tcp mine" && inlog "ufw --force enable"'
A=$(grep -n 'ufw allow 22/tcp' "$T/log" | cut -d: -f1); D=$(grep -n 'ufw default deny incoming' "$T/log" | cut -d: -f1)
check "firewall: allow SSH раньше 'default deny', reset не вызывается, IPV6=no" \
  eval '[ "$A" -lt "$D" ] && ! inlog "ufw reset" && grep -qx IPV6=no "$UFW_DEFAULTS_FILE"'
SSH_CONNECTION="203.0.113.5 50000 198.51.100.1 2222" mod firewall_apply 443 8443 >/dev/null
check "firewall: повторный запуск идемпотентен (5 правил, без дублей)" eval '[ "$(wc -l < "$STUB_DIR/ufw_rules")" = 5 ]'
OUT=$(SSH_CONNECTION="203.0.113.5 50000 198.51.100.1 2222" mod firewall_remove_ports 443 2222 80)
R=$(cat "$STUB_DIR/ufw_rules")
check "firewall_remove_ports: 443 удалён, 2222 (ssh) и 80 (чужое) оставлены, 8443 на месте" \
  eval '! grep -qx "443/tcp vpn-setup" <<<"$R" && has "$R" "2222/tcp ssh" && has "$R" "80/tcp mine" && has "$R" "8443/tcp vpn-setup"'

new_env
OUT=$(PATH="$HERE/stubs-sshd-fail:$PATH" mod firewall_apply 443); RC=$?
check "firewall: SSH-порт не найден → die, ufw enable/default deny НЕ вызывались" \
  eval '[ "$RC" != 0 ] && has "$OUT" "DIE" && ! inlog "ufw --force enable" && ! inlog "ufw enable" && ! inlog "default deny" && ! inlog "ufw allow"'
new_env; OUT=$(mod firewall_apply 443 abc); RC=$?
check "firewall: неверный порт → die до любых изменений ufw" eval '[ "$RC" != 0 ] && ! inlog "ufw "'

# ---------------- fail2ban ----------------
new_env; echo 3 > "$STUB_DIR/f2b_up_after"
OUT=$(SSH_CONNECTION="203.0.113.5 50000 198.51.100.1 2222" mod fail2ban_apply); RC=$?; J=$(cat "$F2B_JAIL_FILE" 2>/dev/null)
check "fail2ban: jail записан (port=22,2222, systemd, increment, ignoreip с IP админа)" \
  eval '[ "$RC" = 0 ] && has "$J" "port = 22,2222" && has "$J" "backend = systemd" && has "$J" "bantime.increment = true" && has "$J" "findtime = 10m" && has "$J" "ignoreip = 127.0.0.1/8 ::1 203.0.113.5"'
check "fail2ban: restart + опрос status до готовности (3 попытки, 2 sleep), без 'sleep 3'" \
  eval 'inlog "systemctl restart fail2ban" && [ "$(grep -c "status sshd" "$T/log")" = 3 ] && [ "$(grep -c "^sleep 1" "$T/log")" = 2 ] && has "$OUT" "активен"'
rm -f "$STUB_DIR/f2b_calls"
OUT=$(SSH_CONNECTION="198.51.100.77 50000 198.51.100.1 22" mod fail2ban_apply); J=$(cat "$F2B_JAIL_FILE")
check "fail2ban: повтор с другого IP — старый IP админа сохранён" eval 'has "$J" "203.0.113.5 198.51.100.77"'
touch "$STUB_DIR/f2b_test_fail"; OUT=$(mod fail2ban_apply); RC=$?; J2=$(cat "$F2B_JAIL_FILE" 2>/dev/null)
check "fail2ban: -t провалился при существующем файле → прежний файл восстановлен, warn, rc=0" eval '[ "$RC" = 0 ] && has "$OUT" WARN && [ "$J" = "$J2" ]'
new_env; touch "$STUB_DIR/f2b_test_fail"; OUT=$(mod fail2ban_apply); RC=$?
check "fail2ban: -t провалился → файл удалён, restart не вызывался, rc=0" eval '[ "$RC" = 0 ] && [ ! -e "$F2B_JAIL_FILE" ] && ! inlog "restart fail2ban"'
new_env; touch "$STUB_DIR/f2b_never"; F2B_WAIT=3; OUT=$(F2B_WAIT=3 mod fail2ban_apply); RC=$?
check "fail2ban: jail не поднялся → warn после таймаута, установка не прерывается" eval '[ "$RC" = 0 ] && has "$OUT" "WARN fail2ban не поднял" && [ "$(grep -c "status sshd" "$T/log")" = 3 ]'
new_env; touch "$STUB_DIR/fail_restart_fail2ban"; OUT=$(mod fail2ban_apply); RC=$?
check "fail2ban: systemctl restart упал → warn, rc=0" eval '[ "$RC" = 0 ] && has "$OUT" WARN'

# ---------------- ssh_add_pubkey ----------------
new_env; ssh-keygen -q -t ed25519 -N "" -C test@k1 -f "$T/k1" >/dev/null; K1=$(cat "$T/k1.pub")
ssh-keygen -q -t rsa -b 2048 -N "" -C test@k2 -f "$T/k2" >/dev/null; K2=$(cat "$T/k2.pub")
FP1=$(ssh-keygen -lf "$T/k1.pub" | awk '{print $2}'); FP2=$(ssh-keygen -lf "$T/k2.pub" | awk '{print $2}')
rmdir "$T/root/.ssh"; OUT=$(mod ssh_add_pubkey "  $K1"$'\r'); RC=$?
check "add_pubkey: валидный ed25519 (с пробелами/CR) добавлен, права 700/600 root" \
  eval '[ "$RC" = 0 ] && grep -qxF "$K1" "$SSH_AUTHKEYS" && [ "$(stat -c %a:%U "$T/root/.ssh")" = 700:root ] && [ "$(stat -c %a:%U "$SSH_AUTHKEYS")" = 600:root ]'
mod ssh_add_pubkey "${K1% *} other-comment" >/dev/null
check "add_pubkey: повтор (другой комментарий) не дублирует" eval '[ "$(wc -l < "$SSH_AUTHKEYS")" = 1 ]'
printf 'no-newline-at-end' >> "$SSH_AUTHKEYS"; mod ssh_add_pubkey "$K2" >/dev/null
check "add_pubkey: rsa добавлен отдельной строкой даже без \\n в конце файла" eval 'grep -qxF "$K2" "$SSH_AUTHKEYS"'
OUT=$(mod ssh_add_pubkey "ssh-ed25519 $K1"); RC=$?
check "add_pubkey: двойной префикс 'ssh-ed25519 ssh-ed25519 AAAA' отклонён" eval '[ "$RC" != 0 ] && has "$OUT" "дважды"'
OUT=$(mod ssh_add_pubkey "$(head -1 "$T/k1")"); RC=$?; check "add_pubkey: приватный ключ отклонён" eval '[ "$RC" != 0 ]'
OUT=$(mod ssh_add_pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBROKENBROKEN x"); RC=$?
check "add_pubkey: битый blob отклонён ssh-keygen" eval '[ "$RC" != 0 ] && has "$OUT" "ssh-keygen"'
OUT=$(mod ssh_add_pubkey "ssh-dss AAAAB3NzaC1kc3M x"); RC=$?; check "add_pubkey: неподдерживаемый тип ssh-dss отклонён" eval '[ "$RC" != 0 ]'

# ---------------- harden_ssh ----------------
HF() { echo "$SSHD_DROPIN_DIR/00-hardening.conf"; }
new_env; OUT=$(mod harden_ssh); RC=$?
check "harden: нет authorized_keys → die, файл не создан" eval '[ "$RC" != 0 ] && [ ! -e "$(HF)" ]'
new_env; echo "ssh-ed25519 $K1" > "$SSH_AUTHKEYS"; echo "Accepted publickey for root from 1.2.3.4 port 1 ssh2: ED25519 $FP1" > "$SSH_AUTH_LOG"
OUT=$(mod harden_ssh); RC=$?
check "harden: только строка с двойным префиксом → die (ключ невалиден)" eval '[ "$RC" != 0 ] && has "$OUT" "повторённым типом" && [ ! -e "$(HF)" ]'
new_env; echo "$K1" > "$SSH_AUTHKEYS"; OUT=$(mod harden_ssh); RC=$?
check "harden: нет доказательства входа по ключу → die, файл не создан" eval '[ "$RC" != 0 ] && has "$OUT" "Accepted publickey" && [ ! -e "$(HF)" ]'
echo "Accepted publickey for root from 1.2.3.4 port 1 ssh2: RSA $FP2" > "$SSH_AUTH_LOG"; OUT=$(mod harden_ssh); RC=$?
check "harden: вход был, но другим ключом (не из authorized_keys) → die" eval '[ "$RC" != 0 ] && [ ! -e "$(HF)" ]'
printf 'no-pty %s\n' "$K1" > "$SSH_AUTHKEYS"; sed -i 's/^Include/#Include/' "$SSHD_CONFIG"
echo "Oct 31 sshd[1]: Accepted publickey for root from 1.2.3.4 port 1 ssh2: ED25519 $FP1" > "$STUB_DIR/journal"
cp "$SSHD_CONFIG" "$T/cfg.bak"; OUT=$(mod harden_ssh); RC=$?
check "harden: нет Include в sshd_config → die, sshd_config не тронут" eval '[ "$RC" != 0 ] && has "$OUT" "Include" && cmp -s "$SSHD_CONFIG" "$T/cfg.bak" && [ ! -e "$(HF)" ]'
printf 'PasswordAuthentication yes\nInclude %s/sshd_config.d/*.conf\n' "$T" > "$SSHD_CONFIG"; OUT=$(mod harden_ssh); RC=$?
check "harden: PasswordAuthentication до Include → die" eval '[ "$RC" != 0 ] && has "$OUT" "1: PasswordAuthentication yes" && [ ! -e "$(HF)" ]'
printf 'Include %s/sshd_config.d/*.conf\n' "$T" > "$SSHD_CONFIG"; echo 'PasswordAuthentication yes' > "$SSHD_DROPIN_DIR/0-cloud.conf"
OUT=$(mod harden_ssh); RC=$?
check "harden: другой drop-in раньше перекрывает → откат (файл удалён), reload не вызывался" eval '[ "$RC" != 0 ] && [ ! -e "$(HF)" ] && ! inlog "reload"'
rm "$SSHD_DROPIN_DIR/0-cloud.conf"; OUT=$(PATH="$HERE/stubs-sshd-fail:$PATH" mod harden_ssh); RC=$?
check "harden: sshd -t провалился → файл удалён, die, reload не вызывался" eval '[ "$RC" != 0 ] && [ ! -e "$(HF)" ] && ! inlog "reload"'
echo 'PasswordAuthentication yes' > "$SSHD_DROPIN_DIR/50-cloud-init.conf"; touch "$STUB_DIR/active_ssh"
OUT=$(mod harden_ssh); RC=$?
EFF=$(/usr/sbin/sshd -T -f "$SSHD_CONFIG" 2>/dev/null)
check "harden: успех (журнал, ключ с опциями, 50-cloud-init yes) → passwordauthentication no, reload ssh, откат напечатан" \
  eval '[ "$RC" = 0 ] && [ -f "$(HF)" ] && grep -qx "passwordauthentication no" <<<"$EFF" && grep -qx "permitrootlogin without-password" <<<"$EFF" && inlog "systemctl reload ssh" && has "$OUT" "Откат" && has "$OUT" "НЕ закрывай"'
touch "$STUB_DIR/fail_reload_ssh"; OUT=$(mod harden_ssh); RC=$?
check "harden: reload не удался → restart ssh" eval '[ "$RC" = 0 ] && inlog "systemctl restart ssh"'

# ---------------- итог ----------------
[ "$(sha256sum /etc/ssh/sshd_config /etc/default/ufw /root/.ssh/authorized_keys 2>/dev/null)" = "$ETC_SUMS" ] \
  && ok "реальные /etc/ssh/sshd_config, /etc/default/ufw, /root/.ssh/authorized_keys не изменены" || bad "реальные /etc изменены!"
echo; echo "Итого: PASS=$PASS FAIL=$FAIL"; for f in "${FAILED[@]}"; do echo "  - $f"; done
[ "$FAIL" = 0 ]
