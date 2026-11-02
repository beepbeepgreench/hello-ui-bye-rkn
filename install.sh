#!/usr/bin/env bash
# vpn-setup v1.1.0 — 3X-UI + Xray: Reality-XHTTP, VLESS-enc+Sudoku, XHTTP-enc
# Ubuntu 22.04 / 24.04 / 26.04, amd64/arm64, запуск от root, на ЧИСТОМ сервере.
#
#   Установка:   bash <(curl -fsSL https://raw.githubusercontent.com/beepbeepgreench/hello-ui-bye-rkn/v1.1.0/install.sh)
#   Потом:       bash /root/vpn-setup/install.sh help
#
# Переменные (необязательно, иначе спросит): USERS, SSH_PUBKEY, SNI, PORT_REALITY, PORT_SUDOKU, PORT_XHTTP
set -Eeuo pipefail

SCRIPT_VERSION="v1.1.0"
SELF_URL="https://raw.githubusercontent.com/beepbeepgreench/hello-ui-bye-rkn/v1.1.0/install.sh"
XUI_VERSION="v3.11.0"   # закреплено: проверено с Xray 26.10.21 (Reality-XHTTP, Sudoku, VLESS-enc)
declare -A XUI_SHA256=(
  [amd64]="0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916"
  [arm64]="f50b4c30fd919d018f2f4c3d8db53a4ca027503d581328727770afb116a79d90"
)
STATE=${STATE:-/root/vpn-setup}

c_ok='\033[1;32m'; c_err='\033[1;31m'; c_warn='\033[1;33m'; c_no='\033[0m'
step(){ echo -e "\n${c_ok}==> $*${c_no}"; }
warn(){ echo -e "${c_warn}! $*${c_no}" >&2; }
die(){ echo -e "\n${c_err}ОШИБКА: $*${c_no}" >&2; exit 1; }
trap 'die "строка $LINENO: команда завершилась с ошибкой: $BASH_COMMAND"' ERR
ask(){ # ask VAR "вопрос" "по умолчанию"
  local __v="$1" __q="$2" __d="${3:-}" __a=""
  if [ -n "${!__v:-}" ]; then return 0; fi
  if (: </dev/tty) 2>/dev/null; then read -r -p "$__q${__d:+ [$__d]}: " __a </dev/tty || true; fi
  printf -v "$__v" '%s' "${__a:-$__d}"
}

# ===================== модули =====================
# shellcheck shell=bash
# shellcheck disable=SC2154  # c_ok/c_no, step/warn/die определены в install.sh до модуля
# ---------- lib/ssh.sh: SSH / firewall (ufw) / fail2ban ----------
# Вставляется целиком в install.sh. Только определения функций и констант, без побочных эффектов.
# Главное требование — не закрыть владельцу доступ к его серверу:
#   * firewall включается только если известен хотя бы один реальный порт SSH, порт текущей сессии разрешается всегда;
#   * правила allow добавляются ДО 'default deny', 'ufw reset' не используется;
#   * пароли отключаются только при наличии валидного ключа и подтверждённого входа по нему.
# Пути вынесены в переменные (для тестов); в бою используются значения по умолчанию.
SSHD_CONFIG=${SSHD_CONFIG:-/etc/ssh/sshd_config}
SSHD_DROPIN_DIR=${SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}
SSHD_RUNDIR=${SSHD_RUNDIR:-/run/sshd}
SSH_AUTHKEYS=${SSH_AUTHKEYS:-/root/.ssh/authorized_keys}
SSH_AUTH_LOG=${SSH_AUTH_LOG:-/var/log/auth.log}
SSH_HARDEN_FILE_NAME=00-hardening.conf
UFW_DEFAULTS_FILE=${UFW_DEFAULTS_FILE:-/etc/default/ufw}
F2B_JAIL_FILE=${F2B_JAIL_FILE:-/etc/fail2ban/jail.d/sshd-vpn-setup.local}
F2B_WAIT=${F2B_WAIT:-20}
SSH_KEY_TYPES_RE='(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)'

_ssh_valid_port(){ # 0 если $1 — число 1..65535
  [[ "${1:-}" =~ ^[0-9]{1,5}$ ]] || return 1
  [ $((10#$1)) -ge 1 ] && [ $((10#$1)) -le 65535 ]
}

_ssh_session_port(){ # серверный порт текущей SSH-сессии (4-е поле SSH_CONNECTION), пусто если нет
  local f4=""
  read -r _ _ _ f4 _ <<<"${SSH_CONNECTION:-}" || true
  if _ssh_valid_port "$f4"; then echo $((10#$f4)); fi
  return 0
}

_ssh_is_loopback(){ # 127.x, ::1, [::1], [::ffff:127.x]
  local a=${1#[}; a=${a%]}; a=${a#::ffff:}
  [[ "$a" == 127.* || "$a" == "::1" || "$a" == "localhost" ]]
}
_ssh_is_ephemeral(){ # порт из диапазона исходящих соединений ядра (обычно 32768–60999)
  local lo=32768 hi=60999 r=""
  r=$(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || true)
  if [[ "$r" =~ ^([0-9]+)[[:space:]]+([0-9]+)$ ]]; then lo=${BASH_REMATCH[1]}; hi=${BASH_REMATCH[2]}; fi
  _ssh_valid_port "${1:-}" && [ $((10#$1)) -ge "$lo" ] && [ $((10#$1)) -le "$hi" ]
}

_ssh_socket_ports(){ # порты из ssh.socket (ListenStream), если сокет активен/включён (Ubuntu 24.04+)
  local out="" tok
  if ! systemctl is-active --quiet ssh.socket 2>/dev/null && ! systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
    return 0
  fi
  out=$(systemctl show ssh.socket -p Listen --value 2>/dev/null || true)
  [ -n "$out" ] || out=$(systemctl show ssh.socket -p Listen 2>/dev/null || true)
  # формы: "[::]:22 (Stream)", "0.0.0.0:2222 (Stream)", "22", "Listen=[::]:22 (Stream)"; unix/netlink — пропускаем
  for tok in $out; do
    tok=${tok#Listen=}
    case "$tok" in "("*|/*|@*|vsock:*|"") continue;; esac
    tok=${tok##*:}
    if _ssh_valid_port "$tok"; then echo $((10#$tok)); fi
  done
  return 0
}

_ssh_cfg_ports(){ # stdin: sshd_config или вывод sshd -T; печатает порты из Port и ListenAddress host:port
  awk 'tolower($1)=="port" && $2 ~ /^[0-9]+$/ {print $2}
       tolower($1)=="listenaddress" && $2 ~ /:[0-9]+$/ && $2 ~ /(^\[|^[0-9.]+:|^[^:]+:[0-9]+$)/ {n=split($2,a,":"); print a[n]}'
}

_ssh_ports_found(){ # все найденные порты SSH по одному в строке (без запасного 22), может быть пусто
  local line addr port sock_ports="" out="" f
  {
    _ssh_session_port
    # (b) слушающие сокеты sshd; сокеты одного systemd — только если совпадают с ssh.socket
    sock_ports=$(_ssh_socket_ports)
    echo "$sock_ports"
    out=$(ss -Htlnp 2>/dev/null || true)
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      addr=$(awk '{print $4}' <<<"$line" || true)
      port=${addr##*:}
      _ssh_valid_port "$port" || continue
      # loopback — это не вход SSH, а X11-forwarding MobaXterm (127.0.0.1:6010) или -R туннели
      _ssh_is_loopback "${addr%:*}" && continue
      if [[ "$line" == *'(("sshd'* || "$line" == *',("sshd'* ]]; then
        echo $((10#$port))
      elif [[ "$line" == *'"systemd"'* ]] && grep -qx -- "$((10#$port))" <<<"$sock_ports"; then
        echo $((10#$port))
      fi
    done <<<"$out"
    # уже установленные входящие SSH-сессии (работает и под sudo, где SSH_CONNECTION нет)
    out=$(ss -Htnp state established 2>/dev/null || true)
    while IFS= read -r line; do
      [[ "$line" == *'"sshd'* ]] || continue
      addr=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^users:/){print $(i-2); exit}}' <<<"$line" || true)
      port=${addr##*:}
      # sshd как клиент проброса (туннель в панель): локальный адрес loopback или эфемерный порт — не вход SSH
      _ssh_is_loopback "${addr%:*}" && continue
      _ssh_is_ephemeral "$port" && continue
      if _ssh_valid_port "$port"; then echo $((10#$port)); fi
    done <<<"$out"
    # (d) sshd -T (без /run/sshd падает с "Missing privilege separation directory")
    if command -v sshd >/dev/null 2>&1; then
      install -d -m 755 "$SSHD_RUNDIR" 2>/dev/null || true
      out=$(sshd -T -f "$SSHD_CONFIG" 2>/dev/null || true)
      _ssh_cfg_ports <<<"$out" || true
    fi
    # (e) строки Port в конфиге и drop-in'ах
    for f in "$SSHD_CONFIG" "$SSHD_DROPIN_DIR"/*.conf; do
      [ -r "$f" ] || continue
      _ssh_cfg_ports < "$f" 2>/dev/null || true
    done
  } | while IFS= read -r port; do
        if _ssh_valid_port "$port"; then echo $((10#$port)); fi
      done | sort -un
  return 0
}

detect_ssh_ports(){ # печатает уникальные порты SSH через пробел; 22 — только если не найдено ничего
  local ports=""
  ports=$(_ssh_ports_found | tr '\n' ' ' || true)
  ports=${ports%% }; ports=${ports% }
  echo "${ports:-22}"
  return 0
}

_ssh_looks_like_ip(){ # IPv4 или IPv6 (не ":0" и не имя хоста)
  [[ "${1:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "${1:-}" =~ ^[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*$ ]]
}

ssh_client_ip(){ # IP клиента текущей SSH-сессии, пусто если не SSH
  local ip="" w=""
  read -r ip _ <<<"${SSH_CONNECTION:-}" || true
  if ! _ssh_looks_like_ip "$ip"; then
    ip=""
    w=$(who am i 2>/dev/null || true)
    if [[ "$w" =~ \(([0-9A-Fa-f:.]+)\) ]]; then ip=${BASH_REMATCH[1]}; fi
  fi
  if ! _ssh_looks_like_ip "$ip"; then
    ip=""
    read -r ip _ <<<"${SSH_CLIENT:-}" || true
  fi
  if _ssh_looks_like_ip "$ip"; then echo "$ip"; fi
  return 0
}

# ---------- firewall (ufw) ----------
firewall_apply(){ # firewall_apply PORT... — идемпотентно: SSH + переданные TCP-порты, затем enable
  local p ssh_ports="" sess="" have
  command -v ufw >/dev/null 2>&1 || die "ufw не установлен (apt-get install ufw)"
  for p in "$@"; do _ssh_valid_port "$p" || die "firewall: неверный порт '$p'"; done
  ssh_ports=$(_ssh_ports_found | tr '\n' ' ' || true)
  sess=$(_ssh_session_port)
  if [ -n "$sess" ]; then
    have=0
    for p in $ssh_ports; do if [ "$p" = "$sess" ]; then have=1; fi; done
    if [ "$have" = 0 ]; then ssh_ports="$ssh_ports $sess"; fi
  fi
  if [ -z "${ssh_ports// /}" ]; then
    die "не удалось определить порт SSH (ни sshd -T, ни ss, ни sshd_config, ни текущая сессия).
  Firewall НЕ включён, чтобы не закрыть доступ к серверу. Проверь: ss -tlnp | grep ssh ; sshd -T | grep -i ^port"
  fi
  if [ -f "$UFW_DEFAULTS_FILE" ]; then
    if grep -q '^IPV6=' "$UFW_DEFAULTS_FILE"; then
      sed -i 's/^IPV6=.*/IPV6=no/' "$UFW_DEFAULTS_FILE"
    else
      echo 'IPV6=no' >> "$UFW_DEFAULTS_FILE"
    fi
  fi
  # сначала allow, потом default deny: если ufw уже активен, deny вступает в силу сразу
  for p in $ssh_ports; do
    ufw allow "${p}/tcp" comment 'ssh' >/dev/null || die "ufw allow ${p}/tcp (ssh) не прошёл — firewall не включаю"
  done
  for p in "$@"; do
    ufw allow "$((10#$p))/tcp" comment 'vpn-setup' >/dev/null || die "ufw allow ${p}/tcp не прошёл"
  done
  # лишние правила 'ssh' от прошлых запусков (порт X11/туннеля MobaXterm) — убрать; текущие SSH-порты не трогаются
  local st="" r
  st=$(ufw status 2>/dev/null || true)
  for r in $(awk '/# ssh$/ && $1 ~ /^[0-9]+\/tcp$/ {sub("/tcp","",$1); print $1}' <<<"$st" | sort -u); do
    if [[ " $ssh_ports " != *" $r "* ]]; then
      ufw delete allow "${r}/tcp" >/dev/null 2>&1 && echo "убрано лишнее правило firewall: ${r}/tcp (не SSH-вход)" || true
    fi
  done
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw default deny routed >/dev/null
  ufw --force enable >/dev/null
  echo "SSH-порты в firewall: ${ssh_ports# }"
  ufw status 2>/dev/null | sed -n '1,14p' || true
  return 0
}

firewall_remove_ports(){ # удаляет только правила 'vpn-setup' для этих портов; SSH-порты не трогает
  local p st="" ssh_ports="" n
  command -v ufw >/dev/null 2>&1 || return 0
  ssh_ports=" $(detect_ssh_ports) $(_ssh_session_port) "
  st=$(ufw status 2>/dev/null || true)
  for p in "$@"; do
    _ssh_valid_port "$p" || { warn "firewall: пропускаю неверный порт '$p'"; continue; }
    p=$((10#$p))
    if [[ "$ssh_ports" == *" $p "* ]]; then warn "порт $p — это SSH, правило оставлено"; continue; fi
    n=$(awk -v r="${p}/tcp" '$1==r && /# vpn-setup/ {c++} END{print c+0}' <<<"$st" || true)
    if [ "${n:-0}" -gt 0 ]; then
      ufw delete allow "${p}/tcp" >/dev/null || warn "не удалось удалить правило ufw ${p}/tcp"
    fi
  done
  return 0
}

# ---------- fail2ban ----------
fail2ban_apply(){ # jail sshd с защитой от самобана; при любых проблемах — warn, не прерывает установку
  local ports="" ip="" ign="127.0.0.1/8 ::1" old="" t backup="" i ok=0
  if ! command -v fail2ban-client >/dev/null 2>&1; then warn "fail2ban не установлен — пропускаю"; return 0; fi
  ports=$(detect_ssh_ports); ports=${ports// /,}
  ip=$(ssh_client_ip)
  # сохраняем ранее добавленные адреса администратора (повторный запуск с другого IP)
  if [ -f "$F2B_JAIL_FILE" ]; then
    old=$(sed -n 's/^[[:space:]]*ignoreip[[:space:]]*=[[:space:]]*//p' "$F2B_JAIL_FILE" 2>/dev/null || true)
    backup=$(mktemp) || { warn "fail2ban: mktemp не сработал — пропускаю"; return 0; }
    cp -p "$F2B_JAIL_FILE" "$backup" || true
  fi
  for t in $old $ip; do
    [[ "$t" =~ ^[0-9A-Fa-f:./]+$ ]] || continue
    if [[ " $ign " != *" $t "* ]]; then ign="$ign $t"; fi
  done
  install -d -m 755 "$(dirname "$F2B_JAIL_FILE")" || { warn "fail2ban: нет каталога jail.d"; return 0; }
  if ! cat > "$F2B_JAIL_FILE" <<EOF
# создано vpn-setup
[sshd]
enabled = true
backend = systemd
port = ${ports}
maxretry = 5
findtime = 10m
bantime = 1h
bantime.increment = true
ignoreip = ${ign}
EOF
  then warn "fail2ban: не удалось записать $F2B_JAIL_FILE"; return 0; fi
  if ! fail2ban-client -t >/dev/null 2>&1; then
    if [ -n "$backup" ]; then mv -f "$backup" "$F2B_JAIL_FILE" || true; else rm -f "$F2B_JAIL_FILE"; fi
    warn "fail2ban: конфигурация не прошла проверку (fail2ban-client -t), настройка jail отменена"
    return 0
  fi
  if [ -n "$backup" ]; then rm -f "$backup"; fi
  systemctl enable fail2ban >/dev/null 2>&1 || true
  if ! systemctl restart fail2ban >/dev/null 2>&1; then
    warn "fail2ban не перезапустился: journalctl -u fail2ban -n 20"; return 0
  fi
  for ((i = 0; i < F2B_WAIT; i++)); do
    if fail2ban-client status sshd >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  if [ "$ok" = 1 ]; then
    echo "fail2ban: jail sshd активен (порты ${ports}, не банятся: ${ign})"
  else
    warn "fail2ban не поднял jail sshd за ${F2B_WAIT} с: journalctl -u fail2ban -n 20"
  fi
  return 0
}

# ---------- ключи SSH ----------
_ssh_double_prefix(){ # 0 если в строке тип ключа повторён: "ssh-ed25519 ssh-ed25519 AAAA..."
  [[ "${1:-}" =~ (^|[[:space:]])${SSH_KEY_TYPES_RE}[[:space:]]+${SSH_KEY_TYPES_RE}([[:space:]]|$) ]]
}

_ssh_key_fp(){ # отпечаток SHA256 одной строки authorized_keys, пусто если ключ невалиден
  local fp=""
  _ssh_double_prefix "$1" && return 0
  fp=$(ssh-keygen -lf - <<<"$1" 2>/dev/null | awk 'NR==1{print $2}' || true)
  if [[ "$fp" == SHA256:* ]]; then echo "$fp"; fi
  return 0
}

ssh_add_pubkey(){ # ssh_add_pubkey "ssh-ed25519 AAAA... comment" — проверить и добавить в authorized_keys root
  local key="${1:-}" blob dir
  key=${key//$'\r'/}
  key=$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"$key" || true)
  [ -n "$key" ] || die "пустой SSH-ключ"
  [[ "$key" != *$'\n'* ]] || die "ключ должен быть одной строкой (вставлено несколько строк)"
  if _ssh_double_prefix "$key"; then
    die "тип ключа указан дважды (например 'ssh-ed25519 ssh-ed25519 AAAA...'). Вставь строку ровно как в файле .pub"
  fi
  [[ "$key" =~ ^${SSH_KEY_TYPES_RE}[[:space:]]+AAAA[A-Za-z0-9+/]+=*([[:space:]].*)?$ ]] \
    || die "это не похоже на публичный SSH-ключ. Нужна строка вида: ssh-ed25519 AAAA... комментарий (содержимое файла .pub, НЕ приватный ключ)"
  ssh-keygen -lf - <<<"$key" >/dev/null 2>&1 || die "ssh-keygen не принял ключ — он повреждён или обрезан при копировании"
  read -r _ blob _ <<<"$key"
  dir=$(dirname "$SSH_AUTHKEYS")
  install -d -m 700 -o root -g root "$dir"
  touch "$SSH_AUTHKEYS"
  if grep -qF -- "$blob" "$SSH_AUTHKEYS"; then
    echo "SSH-ключ уже есть в $SSH_AUTHKEYS"
  else
    if [ -s "$SSH_AUTHKEYS" ] && [ -n "$(tail -c1 "$SSH_AUTHKEYS" || true)" ]; then echo >> "$SSH_AUTHKEYS"; fi
    printf '%s\n' "$key" >> "$SSH_AUTHKEYS"
    echo "SSH-ключ добавлен в $SSH_AUTHKEYS"
  fi
  chown root:root "$dir" "$SSH_AUTHKEYS"
  chmod 700 "$dir"; chmod 600 "$SSH_AUTHKEYS"
  return 0
}

# ---------- отдельная команда: закрыть вход по паролю ----------
harden_ssh(){
  local line fps="" fp n_ok=0 n_bad=0 logs="" acc="" inc_ln="" bad="" f u reloaded=0 eff=""
  local hf="$SSHD_DROPIN_DIR/$SSH_HARDEN_FILE_NAME" prev=""
  # 1. валидные ключи в authorized_keys
  [ -s "$SSH_AUTHKEYS" ] || die "в $SSH_AUTHKEYS нет ключей — отключать пароль нельзя, ты потеряешь доступ.
  Сначала добавь ключ: SSH_PUBKEY='ssh-ed25519 AAAA...' vpn-setup"
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line//$'\r'/}
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    if _ssh_double_prefix "$line"; then
      warn "строка с повторённым типом ключа ('ssh-ed25519 ssh-ed25519 ...') — sshd её НЕ примет: ${line:0:40}..."
      n_bad=$((n_bad + 1)); continue
    fi
    fp=$(_ssh_key_fp "$line")
    if [ -n "$fp" ]; then n_ok=$((n_ok + 1)); fps="$fps $fp"; else n_bad=$((n_bad + 1)); warn "невалидная строка в authorized_keys: ${line:0:40}..."; fi
  done < "$SSH_AUTHKEYS"
  [ "$n_ok" -gt 0 ] || die "в $SSH_AUTHKEYS нет ни одного валидного публичного ключа (ошибочных строк: $n_bad).
  Отключать пароль нельзя — ты потеряешь доступ. Исправь файл и повтори."
  # 2. доказательство, что вход по одному из ЭТИХ ключей работает
  logs=$(journalctl -u ssh -u sshd --since "-24h" --no-pager 2>/dev/null || true)
  if [ -r "$SSH_AUTH_LOG" ]; then logs="$logs"$'\n'"$(cat "$SSH_AUTH_LOG" 2>/dev/null || true)"; fi
  acc=$(grep -F 'Accepted publickey for root' <<<"$logs" || true)
  [ -n "$acc" ] || die "не найдено ни одного входа root по ключу ('Accepted publickey for root') за 24 ч.
  Открой НОВУЮ SSH-сессию с ключом (не закрывая текущую), убедись, что пароль не спрашивался, и повтори."
  n_ok=0
  for fp in $fps; do
    if grep -qF -- "$fp" <<<"$acc"; then n_ok=1; fi
  done
  [ "$n_ok" = 1 ] || die "входы по ключу были, но ни одним из ключей, которые сейчас в $SSH_AUTHKEYS.
  Войди в НОВОЙ сессии с ключом из этого файла и повтори."
  # 3. Include drop-in'ов должен стоять раньше конфликтующих директив (в sshd действует первое значение)
  [ -r "$SSHD_CONFIG" ] || die "нет $SSHD_CONFIG"
  inc_ln=$(awk 'tolower($1)=="include" && $0 ~ /sshd_config\.d\/\*\.conf/ {print NR; exit}' "$SSHD_CONFIG" || true)
  [ -n "$inc_ln" ] || die "в $SSHD_CONFIG нет строки 'Include /etc/ssh/sshd_config.d/*.conf' — drop-in не подействует.
  Автоматически sshd_config не правлю. Добавь эту строку в начало файла вручную и повтори."
  bad=$(awk -v n="$inc_ln" 'NR<n && tolower($1) ~ /^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|permitrootlogin|maxauthtries|logingracetime|match)$/ {print NR": "$0}' "$SSHD_CONFIG" || true)
  [ -z "$bad" ] || die "в $SSHD_CONFIG до строки Include (стр. $inc_ln) есть директивы, которые перекроют настройки:
$bad
  Перенеси их ниже Include или удали, затем повтори."
  # 4. запись drop-in, проверка, перезагрузка
  install -d -m 755 "$SSHD_DROPIN_DIR" "$SSHD_RUNDIR"
  if [ -f "$hf" ]; then prev=$(cat "$hf"); fi
  cat > "$hf" <<'EOF'
# создано vpn-setup (vpn-setup harden-ssh). Откат: удалить файл и systemctl reload ssh
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 6
LoginGraceTime 30
EOF
  chmod 644 "$hf"
  _harden_undo(){ if [ -n "$prev" ]; then printf '%s\n' "$prev" > "$hf"; else rm -f "$hf"; fi; }
  if ! sshd -t -f "$SSHD_CONFIG" 2>/dev/null; then
    _harden_undo; die "sshd -t не прошёл с новыми настройками — изменения отменены, sshd не перезагружался"
  fi
  eff=$(sshd -T -f "$SSHD_CONFIG" 2>/dev/null || true)
  if ! grep -qx 'passwordauthentication no' <<<"$eff" || ! grep -qx 'kbdinteractiveauthentication no' <<<"$eff"; then
    _harden_undo
    die "после записи $hf sshd всё равно разрешает пароль (другой файл в $SSHD_DROPIN_DIR перекрывает настройку). Изменения отменены.
  Проверь: grep -ri password $SSHD_DROPIN_DIR"
  fi
  if grep -qiE '^[[:space:]]*Match[[:space:]]' "$SSHD_CONFIG" "$SSHD_DROPIN_DIR"/*.conf 2>/dev/null; then
    warn "в конфиге sshd есть блоки Match — для совпавших подключений настройки могут отличаться"
  fi
  for u in ssh sshd; do
    if systemctl is-active --quiet "$u" 2>/dev/null; then
      if systemctl reload "$u" 2>/dev/null || systemctl restart "$u"; then reloaded=1; break; fi
    fi
  done
  if [ "$reloaded" = 0 ]; then
    warn "служба ssh/sshd не активна — новые настройки применятся при следующем запуске (ssh.socket)"
  fi
  eff=$(sshd -T -f "$SSHD_CONFIG" 2>/dev/null || true)
  grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin) ' <<<"$eff" || true
  echo -e "${c_ok}Готово: вход по паролю отключён. НЕ закрывай эту сессию, пока не проверишь вход по ключу в НОВОЙ.${c_no}"
  echo "Откат: rm $hf && (systemctl reload ssh || systemctl restart ssh)"
  return 0
}

# shellcheck shell=bash
# ---------- lib/ops.sh: status / backup / links / uninstall / help ----------
# Вставляется в install.sh целиком. На верхнем уровне — только определения функций.
# Все системные пути переопределяются переменными окружения (для тестов):
#   XUI_DIR XUI_DB XUI_ETC XUI_LOG XUI_UNIT XUI_CLI CRON_FILE FINAL_BACKUP_DIR DRY_RUN UNINSTALL_CONFIRM

_ops_paths(){
  XUI_DIR=${XUI_DIR:-/usr/local/x-ui}
  XUI_DB=${XUI_DB:-/etc/x-ui/x-ui.db}
  XUI_ETC=${XUI_ETC:-$(dirname "$XUI_DB")}
  XUI_LOG=${XUI_LOG:-/var/log/x-ui}
  XUI_UNIT=${XUI_UNIT:-/etc/systemd/system/x-ui.service}
  XUI_CLI=${XUI_CLI:-/usr/bin/x-ui}
  CRON_FILE=${CRON_FILE:-/etc/cron.d/vpn-setup-backup}
  FINAL_BACKUP_DIR=${FINAL_BACKUP_DIR:-/root}
  STATE=${STATE:-/root/vpn-setup}
  local a="${ARCH:-}"
  if [ -z "$a" ]; then
    case "$(uname -m)" in aarch64) a=arm64;; *) a=amd64;; esac
  fi
  XRAY_BIN=${XRAY_BIN:-$XUI_DIR/bin/xray-linux-$a}
}

# _ops_make_backup OUT [allow_no_db] — снимок базы панели + секреты из $STATE в tgz (600).
_ops_make_backup(){
  local out="$1" allow_no_db="${2:-}" tmp res
  local -a items=()
  tmp=$(mktemp -d "$(dirname "$out")/.vpn-backup.XXXXXX") || die "не удалось создать временный каталог для бэкапа"
  chmod 700 "$tmp"
  if [ -f "$XUI_DB" ]; then
    if ! sqlite3 -cmd ".timeout 10000" "$XUI_DB" ".backup \"$tmp/x-ui.db\"" >/dev/null 2>"$tmp/err"; then
      res=$(cat "$tmp/err" 2>/dev/null || true); rm -rf "$tmp"
      die "sqlite3 .backup не удался ($XUI_DB): $res"
    fi
    res=$(sqlite3 "$tmp/x-ui.db" 'PRAGMA integrity_check;' 2>&1) || res="ошибка sqlite3: $res"
    if [ "$res" != ok ]; then rm -rf "$tmp"; die "копия базы не прошла PRAGMA integrity_check: $res"; fi
    chmod 600 "$tmp/x-ui.db"
    items+=(-C "$tmp" x-ui.db)
  elif [ -n "$allow_no_db" ]; then
    warn "база панели $XUI_DB не найдена — в архив попадут только файлы из $STATE"
  else
    rm -rf "$tmp"; die "база панели $XUI_DB не найдена"
  fi
  local -a st=()
  local f
  for f in keys panel.env config.env; do
    if [ -e "$STATE/$f" ]; then st+=("$f"); fi
  done
  if [ "${#st[@]}" -gt 0 ]; then items+=(-C "$STATE" "${st[@]}"); fi
  if [ "${#items[@]}" -eq 0 ]; then rm -rf "$tmp"; die "нечего сохранять: нет ни базы, ни файлов в $STATE"; fi
  if ! ( umask 077; tar -czf "$tmp/out.tgz" "${items[@]}" ) 2>"$tmp/err"; then
    res=$(cat "$tmp/err" 2>/dev/null || true); rm -rf "$tmp"; die "tar не удался: $res"
  fi
  if ! tar -tzf "$tmp/out.tgz" >/dev/null 2>&1; then rm -rf "$tmp"; die "созданный архив не читается"; fi
  chmod 600 "$tmp/out.tgz"
  mv -f "$tmp/out.tgz" "$out" || { rm -rf "$tmp"; die "не удалось записать $out"; }
  rm -rf "$tmp"
}

ops_backup(){ # ops_backup [quiet]
  _ops_paths
  local quiet="${1:-}" bdir="$STATE/backup" log sz out ts old n=0
  [ "$quiet" = quiet ] || quiet=""
  command -v sqlite3 >/dev/null 2>&1 || die "нет sqlite3: apt-get install -y sqlite3"
  install -d -m 700 "$bdir"
  log="$bdir/cron.log"
  if [ -f "$log" ]; then   # ротация лога cron: > 1 МБ — оставить последние ~200 КБ (inode тот же, cron пишет с O_APPEND)
    sz=$(stat -c %s "$log" 2>/dev/null || echo 0)
    if [ "${sz:-0}" -gt 1048576 ]; then
      if tail -c 200000 "$log" > "$log.tmp" 2>/dev/null; then cat "$log.tmp" > "$log" || true; fi
      rm -f "$log.tmp"
    fi
  fi
  ts=$(date +%Y-%m-%d-%H%M)
  out="$bdir/vpn-$ts.tgz"
  if [ -e "$out" ]; then out="$bdir/vpn-$ts$(date +%S).tgz"; fi
  _ops_make_backup "$out"
  # ротация: только после успешной проверки нового архива; храним 14 новейших
  while IFS= read -r old; do
    n=$((n + 1))
    if [ "$n" -gt 14 ]; then rm -f -- "$old"; fi
  done < <(find "$bdir" -maxdepth 1 -type f -name 'vpn-*.tgz' -printf '%f\n' 2>/dev/null | LC_ALL=C sort -r | sed "s|^|$bdir/|")
  [ -n "$quiet" ] || echo "Бэкап: $out"
  return 0
}

ops_install_backup_cron(){
  _ops_paths
  local min="" new tmp
  install -d -m 700 "$STATE/backup"
  if [ -f "$CRON_FILE" ]; then   # идемпотентно: сохраняем ранее выбранную минуту
    min=$(awk '$2=="3" && $6=="root" && $1 ~ /^[0-9]+$/ {print $1; exit}' "$CRON_FILE" 2>/dev/null) || min=""
  fi
  [[ "$min" =~ ^[0-9]+$ ]] && [ "$min" -lt 60 ] || min=$((RANDOM % 60))
  new=$(printf '%s\n' \
    "# vpn-setup: ежедневный бэкап базы панели и ключей (создано install.sh)" \
    "SHELL=/bin/bash" \
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "$min 3 * * * root bash $(printf '%q' "$STATE/install.sh") backup quiet >> $(printf '%q' "$STATE/backup/cron.log") 2>&1")
  if [ -f "$CRON_FILE" ] && [ "$(cat "$CRON_FILE" 2>/dev/null || true)" = "$new" ]; then
    echo "cron бэкапа уже настроен: ежедневно в 03:$(printf '%02d' "$min")"
    return 0
  fi
  install -d -m 755 "$(dirname "$CRON_FILE")"
  tmp=$(mktemp "$(dirname "$CRON_FILE")/.vpn-setup-cron.XXXXXX")
  printf '%s\n' "$new" > "$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$CRON_FILE"
  echo "cron бэкапа: ежедневно в 03:$(printf '%02d' "$min") → $STATE/backup/ (хранятся 14 последних)"
}

ops_remove_backup_cron(){
  _ops_paths
  if [ -e "$CRON_FILE" ]; then
    if [ "${DRY_RUN:-0}" = 1 ]; then echo "[DRY-RUN] rm -f $CRON_FILE"; else rm -f -- "$CRON_FILE"; echo "cron бэкапа удалён"; fi
  fi
  return 0
}

# ---------- status ----------
_ops_mark(){ # _ops_mark ok|fail|warn "текст"
  case "$1" in
    ok)   echo -e "  ${c_ok:-}✓${c_no:-} $2";;
    fail) echo -e "  ${c_err:-}✗${c_no:-} $2"; _OPS_FAIL=1;;
    *)    echo -e "  ${c_warn:-}!${c_no:-} $2";;
  esac
}
_ops_listeners(){ # адреса, на которых слушает TCP-порт (по одному в строке)
  ss -Htln "sport = :$1" 2>/dev/null | awk '{print $4}' || true
}
_ops_public_addrs(){ # из списка адресов — те, что не loopback
  grep -v -e '^127\.' -e '^\[::1\]:' -e '^::1:' || true
}

ops_status(){
  _ops_paths
  _OPS_FAIL=0
  local out p l pub p_port="" st name
  echo "Состояние VPN-сервера ($(hostname 2>/dev/null || echo '?'), $(date '+%F %T' 2>/dev/null || true))"

  st=$(systemctl is-active x-ui 2>/dev/null) || true
  if [ "$st" = active ]; then _ops_mark ok "служба x-ui: active"; else _ops_mark fail "служба x-ui: ${st:-нет данных} (journalctl -u x-ui -n 30)"; fi

  name=$(basename "$XRAY_BIN"); name=${name:0:15}
  out=$(pgrep -x -- "$name" 2>/dev/null | head -n1) || true
  if [ -n "$out" ]; then _ops_mark ok "процесс Xray запущен (pid $out)"; else _ops_mark fail "процесс Xray ($name) не найден"; fi

  if [ ! -x "$XRAY_BIN" ]; then
    _ops_mark fail "нет исполняемого файла $XRAY_BIN"
  elif [ ! -f "$XUI_DIR/bin/config.json" ]; then
    _ops_mark fail "нет $XUI_DIR/bin/config.json"
  elif out=$(cd "$XUI_DIR/bin" 2>/dev/null && timeout 30 "$XRAY_BIN" run -test -c "$XUI_DIR/bin/config.json" 2>&1); then
    _ops_mark ok "конфиг Xray: проверка run -test пройдена"
  else
    _ops_mark fail "конфиг Xray с ошибкой: $(printf '%s\n' "$out" | grep -v '^$' | tail -n1 || true)"
  fi

  for p in "${PORT_REALITY:-443}" "${PORT_SUDOKU:-8443}" "${PORT_XHTTP:-8080}"; do
    l=$(_ops_listeners "$p" | tr '\n' ' ')
    if [ -n "${l// /}" ]; then _ops_mark ok "порт $p/tcp слушается (${l% })"; else _ops_mark fail "порт $p/tcp НЕ слушается"; fi
  done

  if [ -f "$STATE/panel.env" ]; then
    # shellcheck disable=SC1091
    p_port=$( . "$STATE/panel.env" >/dev/null 2>&1; echo "${P_PORT:-}" ) || p_port=""
  fi
  if [[ ! "$p_port" =~ ^[0-9]+$ ]]; then
    _ops_mark fail "панель: порт не известен ($STATE/panel.env)"
  else
    l=$(_ops_listeners "$p_port")
    pub=$(printf '%s\n' "$l" | grep -v '^$' | _ops_public_addrs | tr '\n' ' ') || pub=""
    if [ -z "$l" ]; then _ops_mark fail "панель: порт $p_port не слушается"
    elif [ -n "${pub// /}" ]; then _ops_mark fail "панель слушает НЕ только 127.0.0.1: ${pub% } (x-ui setting -listenIP 127.0.0.1)"
    elif printf '%s\n' "$l" | grep -v -e '^$' -e '^127\.0\.0\.1:' | grep -c . >/dev/null; then _ops_mark warn "панель: $p_port на loopback, но не только 127.0.0.1"
    else _ops_mark ok "панель: только 127.0.0.1:$p_port"; fi
  fi

  l=$(_ops_listeners 2096)
  pub=$(printf '%s\n' "$l" | grep -v '^$' | _ops_public_addrs | tr '\n' ' ') || pub=""
  if [ -n "${pub// /}" ]; then _ops_mark fail "подписка 2096 слушает наружу: ${pub% }"
  elif [ -n "$l" ]; then _ops_mark ok "подписка 2096: только localhost"
  else _ops_mark ok "подписка 2096: не слушается"; fi

  if ! command -v ufw >/dev/null 2>&1; then
    _ops_mark fail "UFW не установлен"
  else
    out=$(LC_ALL=C timeout 15 ufw status 2>/dev/null) || out=""
    if [[ "$out" == *"Status: active"* ]]; then
      l=$(printf '%s\n' "$out" | awk '$2 ~ /^ALLOW/ && $1 !~ /\(v6\)/ {print $1}' | LC_ALL=C sort -u | tr '\n' ' ') || l=""
      [ -n "$l" ] || l="ничего "
      _ops_mark ok "UFW активен, разрешено: ${l% }"
      for p in "${PORT_REALITY:-443}" "${PORT_SUDOKU:-8443}" "${PORT_XHTTP:-8080}"; do
        case " $l " in *" $p/tcp "*|*" $p "*) ;; *) _ops_mark warn "UFW: порт $p/tcp не разрешён";; esac
      done
    else
      _ops_mark fail "UFW не активен (${out:-нет ответа})"
    fi
  fi

  if ! command -v fail2ban-client >/dev/null 2>&1; then
    _ops_mark fail "fail2ban не установлен"
  elif out=$(timeout 15 fail2ban-client status sshd 2>/dev/null); then
    l=$(printf '%s\n' "$out" | awk -F: '/Currently banned/{gsub(/[ \t]/,"",$2); print $2; exit}') || l=""
    pub=$(printf '%s\n' "$out" | awk -F: '/Total banned/{gsub(/[ \t]/,"",$2); print $2; exit}') || pub=""
    _ops_mark ok "fail2ban: jail sshd активен, забанено сейчас: ${l:-?} (всего: ${pub:-?})"
  else
    _ops_mark fail "fail2ban: jail sshd не активен (journalctl -u fail2ban -n 20)"
  fi

  install -d -m 755 /run/sshd 2>/dev/null || true
  out=$(sshd -T 2>/dev/null | awk '/^passwordauthentication /{print $2; exit}') || true
  case "$out" in
    no)  _ops_mark ok "SSH: вход по паролю выключен";;
    yes) _ops_mark warn "SSH: вход по паролю ВКЛЮЧЁН — после проверки входа по ключу выполни: vpn-setup harden-ssh";;
    *)   _ops_mark warn "SSH: не удалось определить (sshd -T)";;
  esac

  if [ -f /var/run/reboot-required ]; then
    l=$(sort -u /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ') || l=""
    _ops_mark warn "нужна перезагрузка: обновления безопасности${l:+ (${l% })} вступят в силу после команды reboot. VPN пропадёт на 1–2 мин — лучше ночью"
  else
    _ops_mark ok "перезагрузка не требуется"
  fi

  out=$(df -P / 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5" "int($4/1024)}') || out=""
  if [ -n "$out" ]; then
    p=${out% *}; l=${out#* }
    if [ "$p" -ge 90 ]; then _ops_mark fail "диск /: занято $p%, свободно ${l} МБ"
    elif [ "$p" -ge 80 ]; then _ops_mark warn "диск /: занято $p%, свободно ${l} МБ"
    else _ops_mark ok "диск /: занято $p%, свободно ${l} МБ"; fi
  else
    _ops_mark warn "диск /: нет данных"
  fi

  out=$(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} /^SwapTotal:/{s=$2} /^SwapFree:/{f=$2}
             END{if(t>0) printf "%d %d %d %d %d", int(t/1024), int(a/1024), int(a*100/t), int(s/1024), int((s-f)/1024)}' /proc/meminfo 2>/dev/null) || out=""
  if [ -n "$out" ]; then
    read -r l pub p st name <<<"$out"
    if [ "$p" -lt 10 ]; then _ops_mark warn "RAM: свободно ${pub} из ${l} МБ ($p%), swap занят ${name}/${st} МБ"
    else _ops_mark ok "RAM: свободно ${pub} из ${l} МБ ($p%), swap занят ${name}/${st} МБ"; fi
  else
    _ops_mark warn "RAM: нет данных"
  fi

  out=$(find "$STATE/backup" -maxdepth 1 -type f \( -name 'vpn-*.tgz' -o -name 'x-ui-*.db' \) -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -n1) || out=""
  if [ -z "$out" ]; then
    _ops_mark warn "бэкапов нет: vpn-setup backup"
  else
    p=${out%%.*}; l=$(( ($(date +%s) - p) / 3600 ))
    if [ "$l" -gt 48 ]; then _ops_mark warn "последний бэкап $((l / 24)) дн. назад: ${out#* }"
    else _ops_mark ok "последний бэкап $l ч назад: $(basename "${out#* }")"; fi
  fi
  if [ -f "$CRON_FILE" ]; then _ops_mark ok "ежедневный бэкап по cron: включён"
  else _ops_mark warn "ежедневный бэкап по cron не настроен"; fi

  out=$(timeout 10 "$XUI_DIR/x-ui" -v 2>/dev/null | head -n1) || true
  l=$(timeout 10 "$XRAY_BIN" version 2>/dev/null | awk 'NR==1{print $2; exit}') || true
  if [ -n "$out" ] && [ -n "$l" ]; then
    if [ -n "${XUI_VERSION:-}" ] && [ "$out" != "${XUI_VERSION#v}" ]; then
      if [ "$(printf '%s\n%s\n' "$out" "${XUI_VERSION#v}" | sort -V | tail -n 1)" = "${XUI_VERSION#v}" ]; then
        _ops_mark warn "версии: 3X-UI $out устарела (скрипт ставит ${XUI_VERSION#v}) — обнови: vpn-setup (с бэкапом и автооткатом)"
      else
        _ops_mark warn "версии: 3X-UI $out новее проверенной ${XUI_VERSION#v} (обновили кнопкой в панели?) — работает, не трогай; кнопку «Обновить» больше не жми"
      fi
    else _ops_mark ok "версии: 3X-UI $out, Xray $l"; fi
  else
    _ops_mark warn "версии: 3X-UI ${out:-?}, Xray ${l:-?}"
  fi

  out=$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null) || out=""
  l=$(cat /proc/sys/net/core/default_qdisc 2>/dev/null) || l=""
  if [ "$out" = bbr ]; then _ops_mark ok "BBR активен (qdisc ${l:-?})"; else _ops_mark warn "BBR не активен (сейчас: ${out:-?})"; fi

  if [ ! -d /proc/sys/net/ipv6 ]; then
    _ops_mark ok "IPv6: отключён в ядре"
  else
    out=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null) || out=""
    l=$(ip -6 -o addr show scope global 2>/dev/null | awk '{print $2": "$4}' | tr '\n' ' ') || l=""
    if [ "$out" = 1 ] && [ -z "$l" ]; then _ops_mark ok "IPv6: отключён"
    else _ops_mark warn "IPv6 не отключён (default.disable_ipv6=${out:-?}${l:+, адреса: ${l% }})"; fi
  fi

  if declare -F domain_status >/dev/null; then domain_status; fi
  if [ -n "${DOMAIN:-}" ] && [ "${DOMAIN_CERT_MODE:-letsencrypt}" != selfsigned ]; then
    if systemctl is-enabled --quiet certbot.timer 2>/dev/null; then _ops_mark ok "автопродление сертификата: certbot.timer"
    elif [ -f /etc/cron.d/certbot ] || [ -f /etc/cron.d/vpn-setup-certbot ]; then _ops_mark ok "автопродление сертификата: cron"
    else _ops_mark warn "автопродление сертификата не настроено — выполни: vpn-setup domain $DOMAIN"; fi
  fi

  echo
  if [ "$_OPS_FAIL" = 0 ]; then echo -e "${c_ok:-}Критичных проблем нет.${c_no:-}"; return 0; fi
  echo -e "${c_err:-}Есть проблемы (✗) — см. выше.${c_no:-}"
  return 1
}

# ---------- links ----------
ops_links(){ # ops_links [USER]
  _ops_paths
  local want="${1:-}" links="$STATE/links.txt" line user="" n shown=0 found=0 qr=1 cnt=0
  local -A used=()
  [ -s "$links" ] || die "нет файла ссылок $links — сначала выполни установку"
  if [ -n "$want" ] && [[ ! "$want" =~ ^[A-Za-z0-9_-]{1,32}$ ]]; then die "имя '$want': только латиница, цифры, _ и -"; fi
  if ! command -v qrencode >/dev/null 2>&1; then warn "нет qrencode — QR-коды не обновлены (apt-get install -y qrencode)"; qr=0; fi
  if [ "$qr" = 1 ]; then
    install -d -m 700 "$STATE/qr"
    [ -n "$want" ] || find "$STATE/qr" -maxdepth 1 -type f -name '*.png' -delete 2>/dev/null || true
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in
      "### "*)
        user=${line#\#\#\# }
        shown=0
        if [ -z "$want" ] || [ "$user" = "$want" ]; then shown=1; found=1; echo; echo -e "${c_ok:-}=== $user ===${c_no:-}"; fi
        ;;
      vless://*|vmess://*|trojan://*|ss://*)
        if [ -z "$user" ]; then   # файл без заголовков: имя пользователя — хвост метки после последнего '-'
          n=${line##*#}; n=${n##*-}
          if [ -n "$want" ] && [ "$n" != "$want" ]; then continue; fi
          found=1
        elif [ "$shown" != 1 ]; then continue; fi
        echo "$line"
        if [ "$qr" = 1 ]; then
          n=${line##*#}; if [ "$n" = "$line" ]; then n=""; fi
          n=${n#%F0%9F%87%[A-F0-9][A-F0-9]%F0%9F%87%[A-F0-9][A-F0-9]%20}   # флаг страны в названии → убрать из имени файла
          [ -n "${COUNTRY:-}" ] && n="${COUNTRY}_${n}"
          n=${n//[^A-Za-z0-9_-]/_}; n=${n:0:64}; [ -n "$n" ] || n="link"
          if [ -n "${used[$n]:-}" ]; then used[$n]=$(( used[$n] + 1 )); n="$n-${used[$n]}"; else used[$n]=1; fi
          if ( umask 077; qrencode -o "$STATE/qr/$n.png" "$line" ) 2>/dev/null; then cnt=$((cnt + 1)); else warn "QR для $n не создан"; fi
        fi
        ;;
    esac
  done < "$links"
  if [ -n "$want" ] && [ "$found" = 0 ]; then
    die "пользователь '$want' не найден. Есть: $(awk '/^### /{printf "%s ", $2}' "$links" 2>/dev/null || true)"
  fi
  echo
  [ "$qr" = 0 ] || echo "QR-коды ($cnt шт.): $STATE/qr/"
  echo "Это секреты — не пересылай в открытые чаты."
}

# ---------- uninstall ----------
_ops_run(){ # выполнить команду (или показать при DRY_RUN=1); ошибка не прерывает удаление
  if [ "${DRY_RUN:-0}" = 1 ]; then echo "[DRY-RUN] $*"; return 0; fi
  if "$@"; then return 0; fi
  warn "не удалось: $*"
  _OPS_UFAIL=$((_OPS_UFAIL + 1))
  return 0
}
_ops_safe_rm(){ # rm -rf только для абсолютного пути глубиной >= 2 и не из системного списка
  local p="${1%/}"
  case "$p" in
    ""|/|/*/..|*/../*|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/usr/bin|/usr/sbin|/usr/lib|/usr/local|/usr/local/bin|/var|/var/log|/etc/systemd|/etc/systemd/system)
      warn "отказ удалять подозрительный путь '$1'"; _OPS_UFAIL=$((_OPS_UFAIL + 1)); return 0;;
    /*/*) ;;
    *) warn "отказ удалять подозрительный путь '$1'"; _OPS_UFAIL=$((_OPS_UFAIL + 1)); return 0;;
  esac
  if [ -e "$p" ] || [ -L "$p" ]; then _ops_run rm -rf -- "$p"; else echo "  нет $p — пропуск"; fi
}

ops_uninstall(){
  _ops_paths
  _OPS_UFAIL=0
  local dry="${DRY_RUN:-0}" ts final dest ans="" ssh_port="" p
  ts=$(date +%Y-%m-%d-%H%M%S)
  final="$FINAL_BACKUP_DIR/vpn-setup-final-$ts.tgz"
  dest="${STATE%/}.removed-$ts"
  install -d -m 755 /run/sshd 2>/dev/null || true
  ssh_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}') || true

  echo "Будет удалено: 3X-UI ($XUI_DIR, $XUI_ETC, $XUI_LOG, $XUI_UNIT, $XUI_CLI), cron бэкапа,"
  echo "правила UFW для портов ${PORT_REALITY:-443} ${PORT_SUDOKU:-8443} ${PORT_XHTTP:-8080}/tcp."
  echo "Перед удалением: финальный бэкап → $final; $STATE будет переименован в $dest."
  [ -z "${DOMAIN:-}" ] || echo "Свой домен ${DOMAIN}: убирается наш сайт из nginx и порт 80; сертификат и /var/www/${DOMAIN} остаются."
  echo "SSH, правила UFW для SSH, fail2ban и sysctl НЕ трогаются."
  if [ "$dry" = 1 ]; then
    echo -e "${c_warn:-}DRY_RUN=1: ничего не изменяется, только показ действий.${c_no:-}"
  elif [ "${UNINSTALL_CONFIRM:-}" != yes ]; then
    if (: </dev/tty) 2>/dev/null; then read -r -p "Для подтверждения введи слово удалить: " ans </dev/tty || ans=""; fi
    [ "$ans" = "удалить" ] || die "удаление отменено (нужно ввести 'удалить' или задать UNINSTALL_CONFIRM=yes)"
  fi

  step "Удаление 1/6: финальный бэкап"
  if [ "$dry" = 1 ]; then
    echo "[DRY-RUN] бэкап базы $XUI_DB + $STATE/{keys,panel.env,config.env} → $final"
  elif [ -f "$XUI_DB" ] || [ -d "$STATE" ]; then
    install -d -m 700 "$FINAL_BACKUP_DIR"
    _ops_make_backup "$final" allow_no_db   # при ошибке — die, ничего ещё не удалено
    echo "финальный бэкап: $final"
  else
    warn "нет ни базы, ни $STATE — бэкап пропущен"; final=""
  fi

  step "Удаление 2/6: остановка x-ui"
  if command -v systemctl >/dev/null 2>&1; then
    _ops_run systemctl disable --now x-ui.service
  else
    warn "systemctl не найден — пропуск"
  fi

  step "Удаление 3/6: файлы 3X-UI"
  _ops_safe_rm "$XUI_DIR"
  _ops_safe_rm "$XUI_ETC"
  _ops_safe_rm "$XUI_LOG"
  _ops_safe_rm "$XUI_UNIT"
  _ops_safe_rm "$XUI_CLI"
  if command -v systemctl >/dev/null 2>&1; then _ops_run systemctl daemon-reload; fi

  step "Удаление 4/6: cron бэкапа"
  ops_remove_backup_cron

  step "Удаление 5/6: правила UFW для портов VPN"
  local -a ports=()
  for p in "${PORT_REALITY:-443}" "${PORT_SUDOKU:-8443}" "${PORT_XHTTP:-8080}"; do
    if [ -n "$ssh_port" ] && [ "$p" = "$ssh_port" ]; then warn "порт $p совпадает с SSH — правило оставлено"; continue; fi
    if [[ "$p" =~ ^[0-9]+$ ]]; then ports+=("$p"); fi
  done
  if [ "${#ports[@]}" -eq 0 ]; then
    echo "  нечего удалять"
  elif declare -F firewall_remove_ports >/dev/null; then
    _ops_run firewall_remove_ports "${ports[@]}"
  elif command -v ufw >/dev/null 2>&1; then
    for p in "${ports[@]}"; do _ops_run ufw --force delete allow "$p/tcp"; done
  else
    warn "ufw не найден — пропуск"
  fi

  if [ -n "${DOMAIN:-}" ] && declare -F domain_disable >/dev/null; then
    echo "  свой домен $DOMAIN: убираю наш сайт из nginx и порт 80 (сертификат и файлы сайта остаются)"
    _ops_run domain_disable
  fi
  if [ -f /etc/cron.d/vpn-setup-certbot ]; then _ops_run rm -f /etc/cron.d/vpn-setup-certbot; fi

  step "Удаление 6/6: каталог состояния"
  if [ -d "$STATE" ]; then
    _ops_run mv -- "$STATE" "$dest"
    _ops_run chmod 700 "$dest"
  else
    echo "  нет $STATE — пропуск"; dest=""
  fi

  echo
  if [ "$dry" = 1 ]; then echo -e "${c_warn:-}DRY_RUN: ничего не изменено.${c_no:-}"
  elif [ "$_OPS_UFAIL" = 0 ]; then echo -e "${c_ok:-}3X-UI удалён.${c_no:-}"
  else echo -e "${c_warn:-}Удаление завершено с ошибками ($_OPS_UFAIL) — см. выше.${c_no:-}"; fi
  [ -z "$final" ] || echo "Финальный бэкап (база + ключи): $final"
  [ -z "$dest" ] || echo "Старые ключи/ссылки/пароли: $dest  — содержит секреты; удали сам, когда не нужно: rm -r $dest"
  cat <<EOF
Оставлено намеренно (откат вручную при желании):
  SSH-hardening:  rm /etc/ssh/sshd_config.d/00-hardening.conf && sshd -t && systemctl restart ssh
  sysctl/BBR/IPv6: rm /etc/sysctl.d/90-vpn.conf /etc/modules-load.d/bbr.conf && reboot
  fail2ban jail:  rm /etc/fail2ban/jail.d/sshd-vpn-setup.local && systemctl restart fail2ban
  UFW остаётся включённым с правилом SSH:  ufw status numbered
  swap (если создавался): swapoff /swapfile && sed -i '\|^/swapfile |d' /etc/fstab && rm /swapfile
EOF
  return 0
}

ops_help(){
  cat <<'EOF'
vpn-setup — 3X-UI + Xray (Reality-XHTTP, VLESS-enc+Sudoku, XHTTP-enc)

Использование:  vpn-setup               меню (как у x-ui): все действия по номерам
                vpn-setup [команда]     то же без меню (bash /root/vpn-setup/install.sh [команда])

  install           установка или повторная установка/проверка без меню
  update            обновить скрипт с GitHub и применить (пользователи и ссылки сохраняются)
  panel             как зайти в панель 3X-UI (SSH-туннель): готовые шаги для Windows/macOS/MobaXterm/PuTTY/телефона
  precheck [ПОРТ]   ДО установки: проверить, доходят ли данные с домашнего ПК до этого IP
                    (на ПК в это время: bash check-server.sh IP ПОРТ)
  (без команды)     в терминале — меню; без терминала (cron, скрипт) или с USERS=/DOMAIN=/SNI= — установка.
                    Повторный запуск безопасен: новые имена из USERS добавляются, старые ссылки не меняются
  harden-ssh        отключить вход по паролю (только после проверки входа по ключу!)
  sni [ДОМЕН]       подобрать/проверить сайт маскировки Reality (без аргумента — подбор)
  domain ДОМЕН|off  свой домен: Reality маскируется под твой настоящий сайт на этом сервере (см. README)
  site [ШАБЛОН]     сайт-заглушка на своём домене: список шаблонов / сменить шаблон
  status            проверка состояния: службы, порты, firewall, fail2ban, SSH, диск, RAM,
                    бэкапы, версии; код выхода 1, если есть ✗
  links [ИМЯ]       показать ссылки (всех или одного пользователя) и пересоздать QR в /root/vpn-setup/qr/
  backup            бэкап базы панели и ключей в /root/vpn-setup/backup/ (хранятся 14 последних)
  uninstall         удалить 3X-UI (с финальным бэкапом в /root; SSH и firewall для SSH не трогает).
                    Подтверждение: ввести 'удалить' или UNINSTALL_CONFIRM=yes; DRY_RUN=1 — только показать
  version           версия скрипта и 3X-UI
  help              эта справка

Переменные установки: USERS, SSH_PUBKEY, SNI, DOMAIN, SITE_TEMPLATE, COUNTRY, PORT_REALITY, PORT_SUDOKU, PORT_XHTTP
  (VPN_SETUP_MENU=0 — не показывать меню)
EOF
}

# lib/domain.sh — режим «свой домен» (Reality steal-oneself).
# Reality на :443 отдаёт «чужим» (сканерам, ТСПУ, браузеру) настоящий сайт этого же сервера:
#   клиент VPN ──TLS(SNI=домен)──> Xray :443 ── свой (ключ Reality) ──> VPN
#   сканер     ──TLS(SNI=домен)──> Xray :443 ── чужой ──> nginx 127.0.0.1:DOMAIN_PORT (LE-сертификат, сайт-заглушка)
#   :80 (nginx, публично) — только ACME webroot и 301 на https://домен
# Ожидает из install.sh: STATE, warn, die, step, firewall_apply/firewall_remove_ports (lib/ssh.sh).
# Переопределения для тестов/особых случаев:
#   DOMAIN_SKIP_DNS=1        не проверять A/AAAA-записи домена
#   DOMAIN_CERT_MODE=letsencrypt|staging|selfsigned   (по умолчанию letsencrypt; selfsigned — только тесты)
#   DOMAIN_PORT=N            локальный TLS-порт nginx (иначе первый свободный из 9443..9499)
#   DOMAIN_NGINX_DIR, DOMAIN_WWW_ROOT, DOMAIN_LE_DIR — каталоги (тесты)

DOMAIN_NGINX_DIR=${DOMAIN_NGINX_DIR:-/etc/nginx}
DOMAIN_WWW_ROOT=${DOMAIN_WWW_ROOT:-/var/www}
DOMAIN_LE_DIR=${DOMAIN_LE_DIR:-/etc/letsencrypt}
DOMAIN_SELF_DIR=${DOMAIN_SELF_DIR:-/etc/ssl/vpn-setup}
DOMAIN_CONF_NAME=vpn-setup-domain.conf
DOMAIN_HOOK=${DOMAIN_HOOK:-$DOMAIN_LE_DIR/renewal-hooks/deploy/vpn-setup-nginx.sh}
# слова, по которым домен сразу выглядит как VPN (проверяются в имени без зоны)
DOMAIN_BAD_WORDS="vpn proxy prox trojan vless vmess xray v2ray v2fly wireguard wg tunnel tun2 socks shadow ss-
 reality outline amnezia hysteria tor- bypass unblock obhod rkn freenet antizapret zapret впн прокси обход туннел"
DOMAIN_CF_NETS="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18
 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14
 172.64.0.0/13 131.0.72.0/22"

# ---------- имя ----------
domain_normalize(){ # печатает домен в ASCII (punycode) нижним регистром; 1 — некорректно
  local d="${1:-}"
  d=$(python3 -I -c 'import sys
d=sys.argv[1].strip().rstrip(".").lower()
for p in ("https://","http://"): d=d[len(p):] if d.startswith(p) else d
d=d.split("/")[0]
try: print(d.encode("idna").decode())
except Exception: sys.exit(1)' "$d" 2>/dev/null) || return 1
  [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$ ]] || return 1
  echo "$d"
}
domain_name_check(){ # die, если имя «кричит» VPN; warn для зон .ru/.su/.рф
  local d="$1" base w
  # без зоны; punycode (xn--…) раскодируем, иначе «случайные» буквы дают ложные совпадения
  base=$(python3 -I -c 'import sys; print(".".join(l.encode().decode("idna") if l.startswith("xn--") else l for l in sys.argv[1].split(".")[:-1]))' "$d" 2>/dev/null) || base=${d%.*}
  for w in $DOMAIN_BAD_WORDS; do
    case "$base" in *"$w"*)
      die "домен $d содержит «${w%-}» — по имени сразу видно VPN/прокси. Такие имена ТСПУ и РКН ловят первыми.
  Возьми нейтральное имя (фамилия-фото, блог, мастерская…), без vpn/proxy/trojan/wg/tunnel и т.п." ;;
    esac
  done
  case "$d" in
    *.ru|*.su|*.xn--p1ai|*.xn--d1acj3b)
      warn "домен в зоне .ru/.su/.рф: регистратор обязан приостановить его по требованию РКН, тогда маскировка пропадёт.
  Надёжнее зарубежная зона (.com/.net/.org/.eu/.de…) у зарубежного регистратора." ;;
  esac
  return 0
}

# ---------- DNS ----------
_domain_doh(){ # _domain_doh ИМЯ A|AAAA — адреса через DNS-over-HTTPS (Cloudflare, затем Google)
  local n="$1" t="$2" u out
  for u in "https://cloudflare-dns.com/dns-query?name=$n&type=$t" "https://dns.google/resolve?name=$n&type=$t"; do
    out=$(curl -fsS --max-time 8 -H 'accept: application/dns-json' "$u" 2>/dev/null \
      | python3 -I -c 'import json,sys
t={"A":1,"AAAA":28}[sys.argv[1]]
d=json.load(sys.stdin)
if d.get("Status") not in (0,3): sys.exit(1)
print("\n".join(a["data"] for a in d.get("Answer",[]) if a.get("type")==t))' "$t" 2>/dev/null) && { printf '%s\n' "$out" | sed '/^$/d'; return 0; }
  done
  return 1
}
domain_is_cloudflare(){ # domain_is_cloudflare IP
  python3 -I -c 'import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
sys.exit(0 if any(ip in ipaddress.ip_network(n) for n in sys.argv[2].split()) else 1)' "$1" "$DOMAIN_CF_NETS" 2>/dev/null
}
domain_dns_check(){ # domain_dns_check ДОМЕН IP — A-записи ровно на этот IP, без AAAA и без Cloudflare-прокси
  local d="$1" ip="$2" a aaaa x
  if [ "${DOMAIN_SKIP_DNS:-0}" = 1 ]; then warn "проверка DNS для $d пропущена (DOMAIN_SKIP_DNS=1)"; return 0; fi
  a=$(_domain_doh "$d" A) || die "не удалось проверить DNS домена $d (нет ответа от DNS-over-HTTPS). Повтори позже или DOMAIN_SKIP_DNS=1"
  [ -n "$a" ] || die "у домена $d нет A-записи. В панели регистратора/DNS добавь: $d  A  $ip  (подождать 5–30 мин)"
  for x in $a; do
    if domain_is_cloudflare "$x"; then
      die "$d указывает на Cloudflare ($x) — включено проксирование («оранжевое облако»).
  В Cloudflare → DNS у записи $d переключи Proxy status на «DNS only» (серое облако) и подожди 5 мин."
    fi
  done
  for x in $a; do
    [ "$x" = "$ip" ] || die "$d указывает на $(echo "$a" | tr '\n' ' ')— а этот сервер $ip.
  Исправь A-запись: $d → $ip (лишние A-записи удали), подожди 5–30 мин и повтори."
  done
  aaaa=$(_domain_doh "$d" AAAA) || aaaa=""
  if [ -n "$aaaa" ]; then
    die "у $d есть IPv6-запись (AAAA: $(echo "$aaaa" | tr '\n' ' ')), а на сервере IPv6 выключен —
  сертификат не выпустится, и сайт по IPv6 будет «мёртвым». Удали AAAA-запись и повтори."
  fi
  echo "DNS: $d → $ip ✓"
}

# ---------- nginx ----------
_domain_port_free(){ [ -z "$(ss -Htln "sport = :$1" 2>/dev/null)" ]; }
domain_pick_port(){ # печатает локальный TLS-порт для nginx
  local p
  if [ -n "${DOMAIN_PORT:-}" ]; then echo "$DOMAIN_PORT"; return 0; fi
  # порт, который уже занимает наш же сайт (прошлый запуск оборвался до сохранения config.env)
  p=$(grep -o 'listen 127\.0\.0\.1:[0-9]*' "$DOMAIN_NGINX_DIR/sites-available/$DOMAIN_CONF_NAME" 2>/dev/null | head -n1 | cut -d: -f2) || p=""
  if [ -n "$p" ]; then echo "$p"; return 0; fi
  for p in $(seq 9443 9499); do
    case " ${PORT_REALITY:-443} ${PORT_SUDOKU:-8443} ${PORT_XHTTP:-8080} ${P_PORT:-} " in *" $p "*) continue;; esac
    if _domain_port_free "$p"; then echo "$p"; return 0; fi
  done
  die "нет свободного порта 9443..9499 для локального сайта"
}
_domain_nginx_reload(){
  nginx -t -q 2>/dev/null || { nginx -t || true; return 1; }
  systemctl enable nginx >/dev/null 2>&1 || true
  if systemctl is-active --quiet nginx 2>/dev/null; then systemctl reload nginx; else systemctl restart nginx; fi
}
domain_cert_paths(){ # печатает "fullchain key" для домена в текущем режиме
  local d="$1"
  if [ "${DOMAIN_CERT_MODE:-letsencrypt}" = selfsigned ] \
     || { [ -z "${DOMAIN_CERT_MODE:-}" ] && [ ! -e "$DOMAIN_LE_DIR/live/$d/fullchain.pem" ] && [ -s "$DOMAIN_SELF_DIR/$d.crt" ]; }; then
    echo "$DOMAIN_SELF_DIR/$d.crt $DOMAIN_SELF_DIR/$d.key"
  else
    echo "$DOMAIN_LE_DIR/live/$d/fullchain.pem $DOMAIN_LE_DIR/live/$d/privkey.pem"
  fi
}
_domain_http2_directive(){ # nginx ≥1.25.1: "http2 on;", раньше — параметр listen
  local v
  v=$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9.]*\).*#\1#p')
  if [ -n "$v" ] && [ "$(printf '%s\n1.25.1\n' "$v" | sort -V | head -n1)" = 1.25.1 ]; then echo new; else echo old; fi
}
domain_write_nginx(){ # domain_write_nginx ДОМЕН ПОРТ http|full
  local d="$1" port="$2" mode="$3" crt key h2 listen_tls conf
  conf="$DOMAIN_NGINX_DIR/sites-available/$DOMAIN_CONF_NAME"
  install -d "$DOMAIN_NGINX_DIR/sites-available" "$DOMAIN_NGINX_DIR/sites-enabled" "$DOMAIN_WWW_ROOT/_acme"
  read -r crt key <<<"$(domain_cert_paths "$d")"
  h2=$(_domain_http2_directive)
  if [ "$h2" = new ]; then listen_tls="listen 127.0.0.1:${port} ssl default_server;
    http2 on;"; else listen_tls="listen 127.0.0.1:${port} ssl http2 default_server;"; fi
  {
    cat <<EOF
# vpn-setup: свой домен $d. Файл перезаписывается командой vpn-setup — правь сайт в $DOMAIN_WWW_ROOT/$d
server {
    listen 80 default_server;
    server_name $d _;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ { root $DOMAIN_WWW_ROOT/_acme; default_type text/plain; }
    location / { return 301 https://$d\$request_uri; }
}
EOF
    if [ "$mode" = full ]; then
      cat <<EOF
# TLS только на loopback: снаружи сюда попадают лишь через Reality на :443
server {
    $listen_tls
    server_name $d;
    server_tokens off;
    ssl_certificate     $crt;
    ssl_certificate_key $key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:vpnsetup:5m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;
    root $DOMAIN_WWW_ROOT/$d;
    index index.html;
    error_page 404 /404.html;
    location = /favicon.ico { log_not_found off; access_log off; try_files /favicon.ico =404; }
    location ~ /\. { return 404; }
    location ^~ /data/ {
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Strict-Transport-Security "max-age=31536000" always;
        try_files \$uri =404;
    }
    location / { try_files \$uri \$uri.html \$uri/ =404; }
}
EOF
    fi
  } > "$conf.new"
  mv -f "$conf.new" "$conf"
  ln -sfn "../sites-available/$DOMAIN_CONF_NAME" "$DOMAIN_NGINX_DIR/sites-enabled/$DOMAIN_CONF_NAME"
  # стандартная страница nginx на :80 выдала бы «голый» сервер — выключаем её (файл в sites-available остаётся)
  if [ -L "$DOMAIN_NGINX_DIR/sites-enabled/default" ]; then rm -f "$DOMAIN_NGINX_DIR/sites-enabled/default"; : > "$STATE/domain.default-disabled"; fi
  _domain_nginx_reload || die "nginx не принял конфиг (вывод nginx -t выше). Файл: $conf"
}

# ---------- сайт-заглушка (шаблоны lib/sites/<id>) ----------
# Шаблоны вшиты в install.sh при сборке (build.sh → base64 tar.gz). В исходниках (тесты) берутся из lib/sites.
DOMAIN_CRON_FILE=${DOMAIN_CRON_FILE:-/etc/cron.d/vpn-setup-site}
DOMAIN_SITE_MARK=.vpn-setup-site
DOMAIN_SITES_SRC=${DOMAIN_SITES_SRC:-}
_domain_sites_payload(){ cat <<'SITESEOF'
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
AEABAA==
SITESEOF
}
_domain_sites_dir(){ # печатает каталог с распакованными шаблонами (render.py, card/, status/, rates/)
  local p dir here
  if [ -n "$DOMAIN_SITES_SRC" ] && [ -f "$DOMAIN_SITES_SRC/render.py" ]; then echo "$DOMAIN_SITES_SRC"; return 0; fi
  p=$(_domain_sites_payload)
  if [ ${#p} -lt 100 ]; then   # несобранный модуль: шаблоны рядом, в lib/sites
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    [ -f "$here/sites/render.py" ] || die "шаблоны сайтов не найдены ($here/sites)"
    echo "$here/sites"; return 0
  fi
  dir="$STATE/site/src"
  rm -rf "$dir"; install -d -m 700 "$dir"
  base64 -d <<<"$p" | tar -xzf - -C "$dir" || die "не удалось распаковать шаблоны сайтов"
  echo "$dir"
}
domain_site_list(){ # id|Название|описание
  echo "card|Визитка разработчика|страница фрилансера-веб-разработчика: работы, услуги, контакты"
  echo "status|Статус серверов|страница доступности с живыми данными этого сервера (аптайм, нагрузка, диск)"
  echo "rates|Курсы валют|курсы и конвертер валют, обновляются каждый час с открытого источника"
}
_domain_site_valid(){ domain_site_list | cut -d'|' -f1 | grep -qx -- "${1:-}"; }
_domain_site_hash(){ # хэш шаблона: при обновлении скрипта изменившийся шаблон пересобирается
  local src="$1" id="$2"
  (cd "$src" && find "$id" render.py -type f ! -name '*.pyc' -print0 | sort -z | xargs -0 cat) | sha256sum | cut -c1-16
}
_domain_site_cron(){ # _domain_site_cron ID ДОМЕН — периодическое обновление данных сайта (или удаление)
  local id="$1" d="$2" py dir="$DOMAIN_WWW_ROOT/$2/data" m
  py=$(command -v python3 || echo /usr/bin/python3)
  case "$id" in
    status) printf '# vpn-setup: данные страницы статуса %s\nSHELL=/bin/sh\n* * * * * root %s -I %s %s >/dev/null 2>&1\n' \
              "$d" "$py" "$STATE/site/collect.py" "$dir" > "$DOMAIN_CRON_FILE" ;;
    rates)  m=$(( $(printf '%s' "$d" | cksum | cut -d' ' -f1) % 50 + 5 ))
            printf '# vpn-setup: курсы валют для %s (раз в час)\nSHELL=/bin/sh\n%s * * * * root %s -I %s %s >/dev/null 2>&1\n' \
              "$d" "$m" "$py" "$STATE/site/fetch.py" "$dir" > "$DOMAIN_CRON_FILE" ;;
    *)      rm -f "$DOMAIN_CRON_FILE"; return 0 ;;
  esac
  chmod 644 "$DOMAIN_CRON_FILE"
}
domain_site_deploy(){ # domain_site_deploy ДОМЕН [ID] — сайт из шаблона; свой сайт пользователя не трогаем
  local d="$1" id="${2:-${SITE_TEMPLATE:-card}}" dir src hash old_id="" old_hash="" f list
  _domain_site_valid "$id" || die "нет такого шаблона сайта: $id (варианты: $(domain_site_list | cut -d'|' -f1 | tr '\n' ' '))"
  dir="$DOMAIN_WWW_ROOT/$d"
  if [ -f "$dir/$DOMAIN_SITE_MARK" ]; then
    read -r old_id old_hash < "$dir/$DOMAIN_SITE_MARK" || true
  elif [ -f "$dir/index.html" ]; then
    if grep -q 'written slowly, published rarely' "$dir/index.html" 2>/dev/null; then
      # заглушка прошлой версии vpn-setup — заменяем её файлы
      rm -f "$dir"/index.html "$dir"/about.html "$dir"/404.html "$dir"/style.css "$dir"/favicon.svg "$dir"/robots.txt "$dir"/sitemap.xml
      rm -rf "$dir/notes"
    else
      echo "сайт: в $dir уже есть свой index.html — не трогаю (шаблон «$id» не ставлю)"
      _domain_site_cron none "$d"
      return 0
    fi
  fi
  src=$(_domain_sites_dir)
  hash=$(_domain_site_hash "$src" "$id")
  if [ "$old_id" = "$id" ] && [ "$old_hash" = "$hash" ]; then
    echo "сайт: шаблон «$id» уже стоит"
  else
    if [ -n "$old_id" ]; then   # удаляем только файлы прошлого шаблона по манифесту; чужие файлы остаются
      list=$(tail -n +2 "$dir/$DOMAIN_SITE_MARK")
      while IFS= read -r f; do
        case "$f" in ""|*..*|/*) continue ;; esac
        rm -f "$dir/$f"
      done <<<"$list"
      rm -rf "$dir/data"
    fi
    install -d -m 755 "$dir"
    list=$(python3 -I "$src/render.py" "$id" "$src" "$dir" "$d") || die "не удалось собрать сайт из шаблона «$id»"
    { echo "$id $hash"; echo "$list"; } > "$dir/$DOMAIN_SITE_MARK"
    chmod 644 "$dir/$DOMAIN_SITE_MARK"
    echo "сайт: шаблон «$id» → $dir"
  fi
  install -d -m 700 "$STATE/site"
  case "$id" in
    status) install -m 600 "$src/status/collect.py" "$STATE/site/collect.py"
            python3 -I "$STATE/site/collect.py" "$dir/data" || warn "сбор данных для страницы статуса не удался" ;;
    rates)  install -m 600 "$src/rates/fetch.py" "$STATE/site/fetch.py"
            [ -s "$dir/data/rates.json" ] || python3 -I "$STATE/site/fetch.py" "$dir/data" \
              || warn "курсы пока не загрузились — сайт покажет «загружаются», cron повторит через час" ;;
  esac
  _domain_site_cron "$id" "$d"
  [ -d "$dir/data" ] && chmod 755 "$dir/data"
  chmod -R a+rX "$dir"
  return 0
}
domain_decoy(){ domain_site_deploy "$1" "${SITE_TEMPLATE:-card}"; }   # совместимость
cmd_site(){ # vpn-setup site [ID] — показать / сменить шаблон сайта-маски
  local id="${1:-}" cur line t desc
  require_installed; load_config
  cur=${SITE_TEMPLATE:-card}
  if [ -z "$id" ]; then
    echo "Шаблоны сайта-маски (используется в режиме своего домена):"
    while IFS='|' read -r line t desc; do
      if [ "$line" = "$cur" ]; then printf '  * %-7s %s — %s  (текущий)\n' "$line" "$t" "$desc"
      else printf '    %-7s %s — %s\n' "$line" "$t" "$desc"; fi
    done < <(domain_site_list)
    echo "Сменить: vpn-setup site ID     Свой сайт: положи файлы в /var/www/ДОМЕН (шаблон его не перезапишет)"
    [ -n "${DOMAIN:-}" ] || echo "Сейчас домен не подключён — шаблон будет использован после: vpn-setup domain ДОМЕН"
    return 0
  fi
  _domain_site_valid "$id" || die "нет такого шаблона: $id. Список: vpn-setup site"
  SITE_TEMPLATE="$id"
  if [ -n "${DOMAIN:-}" ]; then domain_site_deploy "$DOMAIN" "$id"; fi
  save_config
  echo "шаблон сайта: $id"
}

# ---------- сертификат ----------
domain_cert(){ # выпуск/проверка сертификата для ДОМЕН
  local d="$1" mode="${DOMAIN_CERT_MODE:-letsencrypt}" crt key
  read -r crt key <<<"$(DOMAIN_CERT_MODE="$mode" domain_cert_paths "$d")"
  if [ "$mode" = selfsigned ]; then
    install -d -m 700 "$DOMAIN_SELF_DIR"
    if [ ! -s "$crt" ]; then
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 90 \
        -subj "/CN=$d" -addext "subjectAltName=DNS:$d" -keyout "$key" -out "$crt" >/dev/null 2>&1 \
        || die "openssl: не удалось создать тестовый сертификат"
      chmod 600 "$key"
    fi
    warn "сертификат самоподписанный (DOMAIN_CERT_MODE=selfsigned) — только для тестов"
    return 0
  fi
  command -v certbot >/dev/null 2>&1 || die "certbot не установлен"
  if [ -s "$crt" ] && openssl x509 -checkend $((30*86400)) -noout -in "$crt" >/dev/null 2>&1; then
    echo "сертификат $d уже есть и действует ещё >30 дней"
  else
    local -a extra=()
    [ "$mode" = staging ] && extra+=(--staging)
    echo "выпускаю сертификат Let's Encrypt для $d (проверка через http://$d/.well-known/…)"
    certbot certonly --webroot -w "$DOMAIN_WWW_ROOT/_acme" -d "$d" --non-interactive --agree-tos \
      --register-unsafely-without-email --keep-until-expiring "${extra[@]}" \
      || die "Let's Encrypt не выдал сертификат для $d. Частые причины: A-запись ещё не обновилась;
  порт 80 закрыт у хостера; включён Cloudflare-прокси. Повтори через 10–30 минут: vpn-setup domain $d"
  fi
  install -d "$(dirname "$DOMAIN_HOOK")"
  printf '#!/bin/sh\n# vpn-setup: перечитать сертификат после продления\nsystemctl reload nginx\n' > "$DOMAIN_HOOK"
  chmod 755 "$DOMAIN_HOOK"
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
}

# ---------- включение / выключение ----------
domain_setup(){ # domain_setup ДОМЕН IP — nginx + сайт + сертификат; печатает в DOMAIN_PORT порт
  local d="$1" ip="$2"
  domain_name_check "$d"
  domain_dns_check "$d" "$ip"
  if ! command -v nginx >/dev/null 2>&1 || { [ "${DOMAIN_CERT_MODE:-letsencrypt}" != selfsigned ] && ! command -v certbot >/dev/null 2>&1; }; then
    echo "ставлю nginx и certbot…"
    command -v nginx >/dev/null 2>&1 || : > "$STATE/domain.nginx-installed"
    # Не даём пакету запустить nginx со стандартным сайтом: в нём "listen [::]:80", а IPv6 на сервере
    # выключен — запуск падает и apt оставляет пакет недонастроенным. Стандартный механизм Debian: policy-rc.d.
    local prc=/usr/sbin/policy-rc.d made_prc=0 rc=0
    if [ ! -e "$prc" ]; then printf '#!/bin/sh\nexit 101\n' > "$prc"; chmod 755 "$prc"; made_prc=1; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=600 nginx certbot >/dev/null || rc=$?
    [ "$made_prc" = 1 ] && rm -f "$prc"
    [ "$rc" = 0 ] || die "apt: не удалось поставить nginx/certbot"
  fi
  DOMAIN_PORT=$(domain_pick_port)   # сохранённый порт переиспользуется (DOMAIN_PORT из config.env)
  domain_site_deploy "$d" "${SITE_TEMPLATE:-card}"
  domain_write_nginx "$d" "$DOMAIN_PORT" http
  domain_cert "$d"
  domain_write_nginx "$d" "$DOMAIN_PORT" full
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do domain_local_probe "$d" "$DOMAIN_PORT" && break; sleep 1; done   # reload nginx асинхронный
  domain_local_probe "$d" "$DOMAIN_PORT" || die "сайт $d не отвечает на 127.0.0.1:$DOMAIN_PORT по TLS 1.3 + HTTP/2"
  echo "свой сайт: https://$d → nginx 127.0.0.1:$DOMAIN_PORT (TLS 1.3, HTTP/2) ✓"
}
domain_local_probe(){ # domain_local_probe ДОМЕН ПОРТ — TLS1.3 + h2 + 200 на /
  local d="$1" port="$2" out
  out=$(curl -sk --noproxy '*' --http2 --tlsv1.3 --max-time 8 -o /dev/null -w '%{http_version} %{http_code}' \
        --resolve "$d:$port:127.0.0.1" "https://$d:$port/" 2>/dev/null) || return 1
  [ "$out" = "2 200" ]
}
domain_disable(){ # убрать наш сайт из nginx (сертификат и файлы сайта остаются), закрыть :80
  local conf="$DOMAIN_NGINX_DIR/sites-available/$DOMAIN_CONF_NAME"
  rm -f "$DOMAIN_NGINX_DIR/sites-enabled/$DOMAIN_CONF_NAME" "$conf" "$DOMAIN_HOOK"
  rm -f "$DOMAIN_CRON_FILE"   # обновление данных сайта (статус/курсы) больше не нужно
  if [ -f "$STATE/domain.nginx-installed" ]; then
    systemctl disable --now nginx >/dev/null 2>&1 || true
    rm -f "$STATE/domain.nginx-installed"
    echo "nginx остановлен (его ставил vpn-setup)"
  elif command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null; then
    if [ -f "$STATE/domain.default-disabled" ] && [ -f "$DOMAIN_NGINX_DIR/sites-available/default" ]; then
      ln -sfn ../sites-available/default "$DOMAIN_NGINX_DIR/sites-enabled/default"
      # стандартный сайт не запустится без IPv6 ("listen [::]:80") — тогда не возвращаем его
      if ! nginx -t -q >/dev/null 2>&1; then
        rm -f "$DOMAIN_NGINX_DIR/sites-enabled/default"
        warn "стандартный сайт nginx не возвращён: он требует IPv6, а IPv6 выключен"
      fi
    fi
    _domain_nginx_reload || warn "nginx -t после удаления нашего сайта не прошёл — проверь: nginx -t"
  fi
  rm -f "$STATE/domain.default-disabled"
  if declare -F firewall_remove_ports >/dev/null; then firewall_remove_ports 80 || true; fi
  echo "режим своего домена выключен (сертификат в $DOMAIN_LE_DIR и сайт в $DOMAIN_WWW_ROOT оставлены)"
}

# ---------- статус ----------
domain_status(){ # строки для ops_status (использует _ops_mark)
  [ -n "${DOMAIN:-}" ] || return 0
  local crt key end days st l
  read -r crt key <<<"$(domain_cert_paths "$DOMAIN")"
  _ops_mark ok "свой домен: $DOMAIN (Reality → nginx 127.0.0.1:${DOMAIN_PORT:-?})"
  st=$(systemctl is-active nginx 2>/dev/null) || true
  if [ "$st" = active ]; then _ops_mark ok "nginx: active"; else _ops_mark fail "nginx: ${st:-нет данных} (systemctl status nginx)"; fi
  if [ -s "$crt" ]; then
    end=$(openssl x509 -enddate -noout -in "$crt" 2>/dev/null | cut -d= -f2) || end=""
    days=$(( ( $(date -d "$end" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
    if [ "$days" -lt 0 ]; then _ops_mark fail "сертификат $DOMAIN истёк — certbot renew; systemctl reload nginx"
    elif [ "$days" -lt 20 ]; then _ops_mark warn "сертификат $DOMAIN: осталось $days дн. (должен продлеваться сам; проверь: certbot renew --dry-run)"
    else _ops_mark ok "сертификат $DOMAIN: ещё $days дн."; fi
  else
    _ops_mark fail "нет сертификата $crt (vpn-setup domain $DOMAIN)"
  fi
  if domain_local_probe "$DOMAIN" "${DOMAIN_PORT:-0}"; then _ops_mark ok "сайт-маска отвечает (TLS 1.3, HTTP/2)"
  else _ops_mark fail "сайт-маска на 127.0.0.1:${DOMAIN_PORT:-?} не отвечает (nginx -t; systemctl status nginx)"; fi
  l=$(_ops_listeners 80 | tr '\n' ' ')
  if [ -n "${l// /}" ]; then _ops_mark ok "порт 80/tcp слушается (для продления сертификата)"; else _ops_mark warn "порт 80 не слушается — сертификат не продлится"; fi
  return 0
}

# ===================== общие функции =====================
load_config(){
  # shellcheck disable=SC1091
  [ -f "$STATE/config.env" ] && . "$STATE/config.env"
  PORT_REALITY=${PORT_REALITY:-443}; PORT_SUDOKU=${PORT_SUDOKU:-8443}; PORT_XHTTP=${PORT_XHTTP:-8080}
  case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; *) die "архитектура $(uname -m) не поддерживается";; esac
  XRAY_BIN=/usr/local/x-ui/bin/xray-linux-${ARCH}
  # shellcheck disable=SC1091
  [ -f "$STATE/panel.env" ] && . "$STATE/panel.env"
  return 0
}
save_config(){
  ( umask 077
    printf 'USERS=%q\nSNI=%q\nPORT_REALITY=%q\nPORT_SUDOKU=%q\nPORT_XHTTP=%q\nPUBLIC_IP=%q\nCOUNTRY=%q\nDOMAIN=%q\nDOMAIN_PORT=%q\nBORROWED_SNI=%q\nSITE_TEMPLATE=%q\nINSTALLED_VERSION=%q\n' \
      "${USERS:-}" "${SNI:-}" "$PORT_REALITY" "$PORT_SUDOKU" "$PORT_XHTTP" "${PUBLIC_IP:-}" "${COUNTRY:-}" \
      "${DOMAIN:-}" "${DOMAIN_PORT:-}" "${BORROWED_SNI:-}" "${SITE_TEMPLATE:-}" "$SCRIPT_VERSION" > "$STATE/config.env" )
}
require_installed(){
  [ -f "$STATE/panel.env" ] && [ -x /usr/local/x-ui/x-ui ] || die "установка не найдена. Сначала: bash install.sh"
}
is_installed(){ [ -f "$STATE/panel.env" ] && [ -x /usr/local/x-ui/x-ui ]; }
self_path(){ # путь к файлу этого скрипта (для запуска подкоманд отдельным процессом)
  if [ -f "$0" ]; then readlink -f "$0"; elif [ -f "$STATE/install.sh" ]; then echo "$STATE/install.sh"; fi
  return 0
}
run_self(){ # run_self КОМАНДА… — подкоманда отдельным процессом: её ошибка (die) не обрывает вызывающего
  local s; s=$(self_path)
  [ -n "$s" ] || { warn "нет файла скрипта ($STATE/install.sh) — шаг пропущен"; return 1; }
  VPN_SETUP_REEXEC=1 bash "$s" "$@"
}
ensure_cert_renewal(){ # автопродление сертификата: certbot.timer, иначе cron (продление вызывает deploy-hook → reload nginx)
  [ "${DOMAIN_CERT_MODE:-letsencrypt}" = selfsigned ] && return 0
  local m
  if systemctl is-enabled --quiet certbot.timer 2>/dev/null; then
    systemctl start certbot.timer >/dev/null 2>&1 || true
    echo "автопродление сертификата: certbot.timer (проверка дважды в сутки)"
  elif [ -f /etc/cron.d/certbot ] || [ -f /etc/cron.d/vpn-setup-certbot ]; then
    echo "автопродление сертификата: cron"
  else
    m=$(( $(od -An -N1 -tu1 /dev/urandom) % 60 ))
    printf 'SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n%s 4,16 * * * root certbot renew -q\n' "$m" \
      > /etc/cron.d/vpn-setup-certbot
    chmod 644 /etc/cron.d/vpn-setup-certbot
    echo "автопродление сертификата: cron /etc/cron.d/vpn-setup-certbot (дважды в сутки)"
  fi
  return 0
}
write_helpers(){
  install -d -m 700 "$STATE" "$STATE/keys"
  cat > "$STATE/provision.py" <<'PYEOF'
#!/usr/bin/env python3
"""Create/refresh 3X-UI inbounds and clients through the panel API.

Idempotent: inbounds are found by tag, clients by email. Secrets live in STATE_DIR.
Env: PANEL_URL TOKEN_FILE STATE_DIR XRAY_BIN PUBLIC_IP USERS SNI
     PORT_REALITY PORT_SUDOKU PORT_XHTTP

SNI change mode: SET_SNI=DOMAIN (+ PANEL_URL TOKEN_FILE STATE_DIR XRAY_BIN, USERS optional) only rewrites
realitySettings.target/serverNames of the vpn-reality inbound, restarts Xray, verifies the config
(rolls back on failure) and regenerates links.txt. Nothing is created.
"""
import json, os, re, secrets, subprocess, sys, time, urllib.request, urllib.error, urllib.parse, pathlib

E = os.environ
URL = E["PANEL_URL"].rstrip("/")
TOKEN = pathlib.Path(E["TOKEN_FILE"]).read_text().strip()
STATE = pathlib.Path(E["STATE_DIR"])
XRAY = E["XRAY_BIN"]
SET_SNI = E.get("SET_SNI", "").strip().lower().rstrip(".")
# Свой домен: Reality пересылает «чужих» на локальный nginx (127.0.0.1:PORT) вместо SNI:443
REALITY_TARGET = E.get("REALITY_TARGET", "").strip()


def die(msg):
    print(f"ОШИБКА: {msg}", file=sys.stderr)
    sys.exit(1)


def api(method, path, body=None, quiet=False):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(URL + path, data=data, method=method, headers={
        "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        if quiet: raise SystemExit(1)
        die(f"{method} {path}: HTTP {e.code}")
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        if quiet: raise SystemExit(1)
        die(f"{method} {path}: панель недоступна ({e})")
    if not res.get("success", False):
        die(f"{method} {path}: {res.get('msg')}")
    return res.get("obj")


def secret(name, gen):
    f = STATE / name
    if not f.exists() or not f.read_text().strip():
        f.write_text(gen() + "\n")
        f.chmod(0o600)
    return f.read_text().strip()


def xray(*args):
    return subprocess.run([XRAY, *args], check=True, capture_output=True, text=True).stdout


def gen_x25519():
    out = xray("x25519")
    priv = re.search(r"PrivateKey:\s*(\S+)", out).group(1)
    pub = re.search(r"(?:PublicKey|Password)[^:]*:\s*(\S+)", out).group(1)
    return json.dumps({"private": priv, "public": pub})


def gen_vlessenc():
    out = xray("vlessenc")
    block = out.split("ML-KEM-768")[-1]  # post-quantum authentication pair
    dec = re.search(r'"decryption":\s*"([^"]+)"', block).group(1)
    enc = re.search(r'"encryption":\s*"([^"]+)"', block).group(1)
    return json.dumps({"decryption": dec, "encryption": enc})


def restart_and_test(on_fail):
    """Apply now and prove Xray accepted it: one bad inbound stops the whole core."""
    api("POST", "/panel/api/server/restartXrayService")
    time.sleep(4)
    cfg = os.path.join(os.path.dirname(XRAY), "config.json")
    t = subprocess.run([XRAY, "run", "-test", "-c", cfg], capture_output=True, text=True)
    if t.returncode != 0:
        on_fail((t.stdout + t.stderr).strip().splitlines()[-1])
    print("Xray: конфиг принят")


def write_links(users=None):
    if not users:  # все клиенты панели — чтобы ссылки старых пользователей не пропадали
        users = sorted({c.get("email") for c in (api("GET", "/panel/api/clients/list") or []) if c.get("email")})
    out = []
    for u in users:
        links = api("GET", f"/panel/api/clients/links/{urllib.parse.quote(u)}") or []
        out.append(f"### {u}")
        out.extend(links)
        out.append("")
    (STATE / "links.txt").write_text("\n".join(out))
    (STATE / "links.txt").chmod(0o600)
    print(f"ссылки: {STATE / 'links.txt'}")


def list_inbounds():
    """Список inbound'ов. Сразу после перезапуска панель может отдать пустой список, пока не дочитала базу
    (видели на 3.11 после обновления) — при повторной установке ждём, пока inbound'ы появятся."""
    lst = api("GET", "/panel/api/inbounds/list") or []
    if not lst and (STATE / "links.txt").exists():
        for _ in range(20):
            time.sleep(1)
            try:
                lst = api("GET", "/panel/api/inbounds/list", quiet=True) or []
            except SystemExit:
                continue
            if lst:
                break
    return lst


def find_ours(lst, tag, port):
    """Наш inbound: по тегу, иначе vless-inbound на нашем порту (если тег переписан панелью)."""
    ib = next((i for i in lst if i.get("tag") == tag), None)
    if ib is None:
        ib = next((i for i in lst if int(i.get("port") or 0) == int(port) and i.get("protocol") == "vless"), None)
        if ib is not None:
            print(f"inbound {tag}: найден по порту {port} (тег {ib.get('tag')!r})")
    return ib


def set_sni(dom):
    """SET_SNI mode: point vpn-reality at another camouflage site; idempotent, with rollback."""
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}", dom):
        die(f"SET_SNI: некорректное доменное имя {dom!r}")
    ib = find_ours(list_inbounds(), "vpn-reality", int(E.get("PORT_REALITY") or 443))
    if not ib:
        die("inbound vpn-reality не найден — сначала выполните полную установку")
    iid = ib["id"]
    # GET returns settings/streamSettings/sniffing as nested objects (older panels: JSON strings);
    # UpdateInbound accepts both and overwrites every editable field from the body, so send the
    # whole object back (settings carries the clients) and change only realitySettings.
    old = api("GET", f"/panel/api/inbounds/get/{iid}")
    old.pop("clientStats", None)
    raw = old["streamSettings"]
    stream = json.loads(raw) if isinstance(raw, str) else json.loads(json.dumps(raw))
    rs = stream.get("realitySettings")
    if stream.get("security") != "reality" or not isinstance(rs, dict):
        die("inbound vpn-reality не использует REALITY — менять SNI нечего")
    was = rs.get("serverNames") or []
    tgt = REALITY_TARGET or f"{dom}:443"
    if rs.get("target") == tgt and was == [dom]:
        print(f"SNI: уже {dom} (inbound id {iid}), изменений нет")
    else:
        was_tgt = rs.get("target")
        rs["target"], rs["serverNames"] = tgt, [dom]
        body = dict(old, streamSettings=json.dumps(stream) if isinstance(raw, str) else stream)
        api("POST", f"/panel/api/inbounds/update/{iid}", body)
        print(f"SNI: {', '.join(was) or '—'} → {dom} (inbound id {iid})"
              + (f", target {was_tgt} → {tgt}" if was_tgt != tgt else ""))

        def rollback(err):
            api("POST", f"/panel/api/inbounds/update/{iid}", old)
            api("POST", "/panel/api/server/restartXrayService")
            die(f"Xray не принял конфиг с новым SNI, возвращён прежний ({', '.join(was)}):\n{err}")
        restart_and_test(rollback)
    write_links(None)  # все клиенты панели


if SET_SNI:
    set_sni(SET_SNI)
    sys.exit(0)

IP = E["PUBLIC_IP"]
USERS = E["USERS"].split()
SNI = E["SNI"]
P_REALITY, P_SUDOKU, P_XHTTP = int(E["PORT_REALITY"]), int(E["PORT_SUDOKU"]), int(E["PORT_XHTTP"])

STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
reality = json.loads(secret("reality.json", gen_x25519))
venc = json.loads(secret("vlessenc.json", gen_vlessenc))
sid = secret("reality.sid", lambda: secrets.token_hex(8))
p_reality = secret("path.reality", lambda: "/" + secrets.token_hex(6))
p_xhttp = secret("path.xhttp", lambda: "/" + secrets.token_hex(6))
sudoku_pw = secret("sudoku.pass", lambda: secrets.token_hex(32))

SNIFF = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": True})
XHTTP_BASE = {"mode": "auto", "host": "", "headers": {}, "noSSEHeader": False, "xPaddingBytes": "100-1000",
              "scMaxEachPostBytes": "1000000", "scMaxBufferedPosts": 30, "scStreamUpServerSecs": "20-80"}

FLAG = E.get("FLAG", "").strip()
def remark(base):
    return f"{FLAG} {base}" if FLAG else base


def set_remark(iid, want):
    """Переименовать inbound (флаг страны в названии); меняется только remark."""
    old = api("GET", f"/panel/api/inbounds/get/{iid}")
    if old.get("remark") == want:
        return False
    old.pop("clientStats", None)
    api("POST", f"/panel/api/inbounds/update/{iid}", dict(old, remark=want))
    print(f"inbound id {iid}: название → {want}")
    return True


INBOUNDS = [
    {"tag": "vpn-reality", "remark": remark("Reality-XHTTP"), "port": P_REALITY,
     "settings": {"clients": [], "decryption": "none", "fallbacks": []},
     "stream": {"network": "xhttp", "security": "reality",
                "xhttpSettings": dict(XHTTP_BASE, path=p_reality),
                "realitySettings": {"show": False, "xver": 0, "target": REALITY_TARGET or f"{SNI}:443", "serverNames": [SNI],
                                    "privateKey": reality["private"], "shortIds": [sid],
                                    "minClientVer": "", "maxClientVer": "", "maxTimediff": 0,
                                    "settings": {"publicKey": reality["public"], "fingerprint": "firefox",
                                                 "serverName": "", "spiderX": "/"}}}},
    {"tag": "vpn-sudoku", "remark": remark("Sudoku-VLESSenc"), "port": P_SUDOKU,
     "settings": {"clients": [], "decryption": venc["decryption"], "encryption": venc["encryption"]},
     "stream": {"network": "tcp", "security": "none",
                "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
                "finalmask": {"tcp": [{"type": "sudoku", "settings": {
                    "password": sudoku_pw, "ascii": "", "customTable": "", "customTables": [],
                    "paddingMin": 0, "paddingMax": 0}}]}}},
    {"tag": "vpn-xhttp", "remark": remark("XHTTP-VLESSenc"), "port": P_XHTTP,
     "settings": {"clients": [], "decryption": venc["decryption"], "encryption": venc["encryption"]},
     "stream": {"network": "xhttp", "security": "none", "xhttpSettings": dict(XHTTP_BASE, path=p_xhttp)}},
]

# Subscription server: off and bound to localhost (phones reject its IP-only TLS anyway).
st = api("POST", "/panel/api/setting/all")
if st.get("subEnable") or st.get("subListen") != "127.0.0.1":
    st["subEnable"], st["subListen"] = False, "127.0.0.1"
    api("POST", "/panel/api/setting/update", st)
    api("POST", "/panel/api/setting/restartPanel")
    for _ in range(30):
        time.sleep(1)
        try:
            api("GET", "/panel/api/inbounds/list", quiet=True); break
        except SystemExit:
            continue
    print("подписка: выключена (только localhost)")

_all = list_inbounds()
ids, new_ids = [], []
for d in INBOUNDS:
    ib = find_ours(_all, d["tag"], d["port"])
    if ib is not None:
        ids.append(ib["id"])
        set_remark(ib["id"], d["remark"])
        if not ib.get("enable", True):
            api("POST", f"/panel/api/inbounds/setEnable/{ib['id']}", {"enable": True})
            print(f"inbound {d['tag']}: был выключен — включаю (id {ib['id']})")
        else:
            print(f"inbound {d['tag']}: уже есть (id {ib['id']})")
        continue
    body = {"remark": d["remark"], "enable": True, "expiryTime": 0, "listen": "", "port": d["port"],
            "protocol": "vless", "tag": d["tag"], "settings": json.dumps(d["settings"]),
            "streamSettings": json.dumps(d["stream"]), "sniffing": SNIFF,
            "shareAddrStrategy": "custom", "shareAddr": IP, "trafficReset": "never"}
    obj = api("POST", "/panel/api/inbounds/add", body)
    ids.append(obj["id"]); new_ids.append(obj["id"])
    print(f"inbound {d['tag']}: создан (id {obj['id']}, порт {d['port']})")

have = {c.get("email") for c in (api("GET", "/panel/api/clients/list") or [])}
for u in USERS:
    if u in have:
        api("POST", f"/panel/api/clients/{urllib.parse.quote(u)}/attach", {"inboundIds": ids})
        print(f"клиент {u}: уже есть, привязан ко всем inbound")
        continue
    client = {"id": xray("uuid").strip(), "email": u, "flow": "", "enable": True, "limitIp": 0, "totalGB": 0,
              "expiryTime": 0, "tgId": 0, "subId": secrets.token_hex(8), "comment": "", "reset": 0}
    api("POST", "/panel/api/clients/add", {"client": client, "inboundIds": ids})
    print(f"клиент {u}: создан")



def disable_new(err):
    for i in new_ids:
        api("POST", f"/panel/api/inbounds/setEnable/{i}", {"enable": False})
    api("POST", "/panel/api/server/restartXrayService")
    die("Xray не принял конфиг, новые inbound выключены, Xray перезапущен без них:\n" + err)


restart_and_test(disable_new)
write_links(None)  # ссылки для ВСЕХ клиентов панели, не только переданных сейчас
PYEOF
  cat > "$STATE/sni.py" <<'PYEOF'
#!/usr/bin/env python3
"""Подбор и проверка сайта маскировки (target/SNI) для Xray REALITY.

Только stdlib + `openssl` CLI (проверка X25519). Работает под `python3 -I`, Python 3.10+.

  sni.py check DOMAIN [--json]                    вердикт OK/WARN/FAIL (код 0/1/2)
  sni.py scan [--neighbors IP] [--limit N] [--json] рейтинг кандидатов (+ соседи по /24)
  sni.py pick [--neighbors IP] [--default DOMAIN] интерактивный выбор; домен — последней строкой stdout

Общие флаги (для тестов): --resolve DOMAIN:IP (можно несколько), --port N, --cafile PATH,
  --no-http, --timeout S, --candidates a,b,c (заменить встроенный список), --non-interactive,
  --server-country CC (страна сервера; иначе — по RDAP для --neighbors), --rdap-offline (без RDAP).
  SNI_RDAP_FILE=fixture.json — ответы RDAP из файла вместо сети:
    {"domain": {"example.de": {RDAP-ответ}}, "ip": {"1.2.3.4": {"country": "DE"}}}

Строгие правила: соседи по /24 — только если имя из сертификата резолвится в IP этого соседа
  (иначе это чужой Reality/прокси) и никогда не по умолчанию; дешёвые TLD, домены моложе 2 лет
  (RDAP) и российский сегмент на зарубежном сервере — FAIL.
"""
import argparse, datetime, ipaddress, json, os, queue, re, shutil, socket, ssl, subprocess, sys, tempfile, threading, time
import urllib.error, urllib.request
from urllib.parse import quote, urlsplit

OK, WARN, FAIL = 0, 1, 2
VNAME = {OK: "OK", WARN: "WARN", FAIL: "FAIL"}
LATENCY_WARN_MS = 150

# Скучные, посещаемые, неполитические сайты на собственной инфраструктуре (не Akamai/CloudFront —
# заведомо CDN-фронтированные убраны); страна — для подсказки. Всё равно проверяется на лету.
# Предпочтение — сайтам, привычным посетителям из РФ (магазины электроники/инструмента, почта,
# железные дороги, финские магазины, которые знали жители Петербурга) и в DE/FI рядом с типичными VPS.
CANDIDATES = [
    ("www.otto.de", "DE"), ("www.lidl.de", "DE"), ("www.hornbach.de", "DE"), ("www.thomann.de", "DE"),
    ("www.reichelt.de", "DE"), ("www.conrad.de", "DE"), ("www.alternate.de", "DE"), ("www.chefkoch.de", "DE"),
    ("www.idealo.de", "DE"), ("www.heise.de", "DE"), ("www.kaufland.de", "DE"), ("www.dm.de", "DE"),
    ("www.verkkokauppa.com", "FI"), ("www.gigantti.fi", "FI"), ("www.tokmanni.fi", "FI"), ("www.motonet.fi", "FI"),
    ("www.s-kanava.fi", "FI"), ("www.posti.fi", "FI"), ("www.vr.fi", "FI"), ("www.k-ruoka.fi", "FI"),
    ("www.postnl.nl", "NL"), ("www.coolblue.nl", "NL"),
    ("www.ica.se", "SE"), ("www.postnord.se", "SE"), ("www.sj.se", "SE"),
    ("www.billa.at", "AT"), ("www.oebb.at", "AT"), ("www.post.at", "AT"),
    ("www.seznam.cz", "CZ"), ("www.mapy.cz", "CZ"), ("www.alza.cz", "CZ"), ("www.cd.cz", "CZ"),
    ("www.inpost.pl", "PL"), ("www.intercity.pl", "PL"), ("www.x-kom.pl", "PL"),
    ("www.rimi.ee", "EE"), ("www.omniva.ee", "EE"), ("www.rimi.lv", "LV"),
    ("www.post.lt", "LT"), ("www.maxima.lt", "LT"),
    ("www.correos.es", "ES"), ("www.mercadona.es", "ES"),
]

# Сайты, которые отказывают посетителям из РФ (geo-block). Reality это не ломает (сайт открывает
# сервер, а не браузер пользователя), но для пользователей из РФ такая маскировка менее естественна.
# Сравнение по регистрируемому домену.
GEOBLOCK_RU = frozenset({"dm.de", "maxima.lt"})

# Дешёвые/«одноразовые» TLD: регистрируют массово под фишинг, спам и чужие панели — FAIL.
SUSPICIOUS_TLDS = frozenset(
    "fun site xyz top shop online click icu buzz cyou monster rest lol quest sbs cfd bond beauty hair "
    "skin makeup boats homes yachts mom autos motorcycles".split())

# Российский сегмент: на зарубежном сервере выглядит неестественно и под особым контролем ТСПУ.
RU_TLDS = frozenset({"ru", "su", "xn--p1ai"})                       # xn--p1ai = .рф
RU_BRANDS = frozenset({"vk", "vkontakte", "vkuser", "userapi", "odnoklassniki", "yandex", "yastatic"})

# Зарезервированные TLD (RFC 2606/6761 и локальные) — RDAP по ним не спрашиваем.
RESERVED_TLDS = frozenset({"test", "example", "invalid", "localhost", "local", "internal", "lan", "home", "arpa"})

# Мини-подмножество Public Suffix List: двухуровневые суффиксы. Остальное — одноуровневый TLD
# (+ эвристика «co./com./… в двухбуквенной зоне», см. registrable()).
MULTI_SUFFIXES = frozenset("""
co.uk org.uk me.uk ltd.uk plc.uk ac.uk gov.uk net.uk com.au net.au org.au edu.au gov.au id.au
co.nz net.nz org.nz co.jp ne.jp or.jp ac.jp co.za com.br net.br com.tr net.tr org.tr
com.ua org.ua net.ua in.ua kiev.ua com.pl net.pl org.pl waw.pl com.cn net.cn org.cn com.hk com.tw
co.kr or.kr com.sg com.my co.in net.in org.in co.id co.il org.il com.mx com.ar co.at or.at com.gr
com.cy com.mt com.ro co.hu com.ee com.lv com.pt com.es msk.ru spb.ru com.ru net.ru org.ru com.by
co.th com.vn com.ph com.pk com.eg com.sa""".split())

# RDAP: возраст домена и страна IP. Таймаут на запрос, общий бюджет на прогон, не больше 4 параллельно.
RDAP_URL = "https://rdap.org"
RDAP_TIMEOUT = 5.0
RDAP_BUDGET = 25.0
AGE_FAIL_DAYS = 2 * 365
AGE_NOTE_DAYS = 5 * 365

# Имена, которые используют все подряд: их SNI на чужом IP — заметный признак.
OVERUSED = ("microsoft", "apple", "icloud", "google", "gstatic", "youtube", "yahoo", "amazon", "aws",
            "cloudflare", "github", "speedtest", "bing", "live", "office", "azure", "samsung", "nvidia",
            "mozilla", "discord", "whatsapp", "telegram", "lovelive-anime", "dl", "swdist", "addons")

# Компактный список крупных CDN (IPv4). Остальное считаем «не CDN».
CDN_RANGES = {
    "Cloudflare": "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 "
                  "108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 "
                  "162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22",
    "Fastly": "23.235.32.0/20 43.249.72.0/22 103.244.50.0/24 103.245.222.0/23 103.245.224.0/24 "
              "104.156.80.0/20 140.248.64.0/18 140.248.128.0/17 146.75.0.0/17 151.101.0.0/16 "
              "157.52.64.0/18 167.82.0.0/17 167.82.128.0/20 167.82.160.0/20 167.82.224.0/20 "
              "172.111.64.0/18 185.31.16.0/22 199.27.72.0/21 199.232.0.0/16",
    "Akamai": "23.0.0.0/12 23.32.0.0/11 23.64.0.0/14 23.192.0.0/11 2.16.0.0/13 95.100.0.0/15 "
              "104.64.0.0/10 184.24.0.0/13 184.50.0.0/15 184.84.0.0/14 96.6.0.0/15 96.16.0.0/15 "
              "72.246.0.0/15 88.221.0.0/16 92.122.0.0/15 173.222.0.0/15",
    "CloudFront": "13.32.0.0/15 13.224.0.0/14 18.64.0.0/14 18.154.0.0/15 18.160.0.0/15 18.164.0.0/15 "
                  "18.172.0.0/15 52.84.0.0/15 54.182.0.0/16 54.192.0.0/16 54.230.0.0/16 54.239.128.0/18 "
                  "65.8.0.0/16 65.9.0.0/17 99.84.0.0/16 99.86.0.0/16 108.138.0.0/15 108.156.0.0/14 "
                  "143.204.0.0/16 205.251.192.0/19 216.137.32.0/19",
}
_CDN_NETS = [(name, ipaddress.ip_network(n)) for name, nets in CDN_RANGES.items() for n in nets.split()]
# Заголовки ответа, по которым CDN видно даже вне известных диапазонов.
CDN_HEADERS = [("server", r"cloudflare", "Cloudflare"), ("cf-ray", r".", "Cloudflare"),
               ("x-amz-cf-id", r".", "CloudFront"), ("via", r"cloudfront", "CloudFront"),
               ("x-served-by", r"cache-", "Fastly"), ("x-fastly-request-id", r".", "Fastly"),
               ("server", r"akamai", "Akamai")]
_2LD = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "gv"}
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")

OPT = argparse.Namespace(resolve={}, port=443, cafile=None, no_http=False, timeout=4.0,
                         server_country=None, rdap_offline=False)


def log(msg=""):
    print(msg, file=sys.stderr, flush=True)


def cdn_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((name for name, net in _CDN_NETS if a.version == net.version and a in net), None)


def registrable(host):
    lab = host.lower().rstrip(".").split(".")
    if len(lab) >= 3 and (".".join(lab[-2:]) in MULTI_SUFFIXES or (lab[-2] in _2LD and len(lab[-1]) == 2)):
        return ".".join(lab[-3:])
    return ".".join(lab[-2:])


def ru_segment(host):
    lab = host.lower().rstrip(".").split(".")
    return lab[-1] in RU_TLDS or registrable(host).split(".")[0] in RU_BRANDS


def geoblocks_ru(host):
    return registrable(host) in GEOBLOCK_RU


# ---------- RDAP (возраст домена, страна IP) ----------

_RDAP = {"cache": {}, "lock": threading.Lock(), "sem": threading.Semaphore(4), "deadline": None,
         "off": False, "fx": None, "fx_loaded": False}


def _rdap_fixture():
    """Содержимое SNI_RDAP_FILE (dict) или None, если переменная не задана."""
    with _RDAP["lock"]:
        if not _RDAP["fx_loaded"]:
            _RDAP["fx_loaded"] = True
            path = os.environ.get("SNI_RDAP_FILE")
            if path:
                try:
                    with open(path, encoding="utf-8") as f:
                        _RDAP["fx"] = json.load(f)
                except (OSError, ValueError) as e:
                    log(f"SNI_RDAP_FILE: не прочитан ({e}) — RDAP отключён")
                    _RDAP["fx"] = {}
        return _RDAP["fx"]


def _rdap_fetch(kind, key):
    fx = _rdap_fixture()
    if fx is not None:  # режим фикстуры: сеть не трогаем вовсе
        v = (fx.get(kind) or {}).get(key)
        return v if isinstance(v, dict) else None
    if OPT.rdap_offline or _RDAP["off"]:
        return None
    if kind == "domain" and key.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return None
    if kind == "ip":
        try:
            if not ipaddress.ip_address(key).is_global:
                return None
        except ValueError:
            return None
    with _RDAP["sem"]:
        now = time.monotonic()
        with _RDAP["lock"]:
            if _RDAP["deadline"] is None:
                _RDAP["deadline"] = now + RDAP_BUDGET
            left = _RDAP["deadline"] - now
        if left < 1 or _RDAP["off"]:
            return None
        req = urllib.request.Request(f"{RDAP_URL}/{kind}/{quote(key)}", headers={
            "Accept": "application/rdap+json, application/json", "User-Agent": "sni.py (reality target check)"})
        try:
            with urllib.request.urlopen(req, timeout=min(RDAP_TIMEOUT, left)) as resp:
                data = json.loads(resp.read(1 << 20).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 429:  # rate limit — больше не долбим в этом прогоне
                _RDAP["off"] = True
            return None
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return None
    return data if isinstance(data, dict) else None


def rdap(kind, key):
    ck = (kind, key)
    with _RDAP["lock"]:
        if ck in _RDAP["cache"]:
            return _RDAP["cache"][ck]
    v = _rdap_fetch(kind, key)
    with _RDAP["lock"]:
        _RDAP["cache"][ck] = v
    return v


def domain_registered(host):
    """Дата регистрации регистрируемого домена (datetime.date) по RDAP или None."""
    j = rdap("domain", registrable(host))
    for ev in (j or {}).get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") == "registration":
            m = re.match(r"(\d{4})-(\d{2})-(\d{2})", str(ev.get("eventDate", "")))
            if m:
                try:
                    return datetime.date(*map(int, m.groups()))
                except ValueError:
                    return None
    return None


def ip_country(ip):
    c = (rdap("ip", ip) or {}).get("country")
    return c.upper() if isinstance(c, str) and re.fullmatch(r"[A-Za-z]{2}", c) else None


def overused(host):
    return next((t for t in OVERUSED for lab in host.lower().split(".")[:-1] if t == lab or
                 (len(t) > 4 and t in lab)), None)


def in_thread(fn, timeout):
    """Выполнить fn с жёстким таймаутом (getaddrinfo нельзя прервать иначе)."""
    box = {}

    def run():
        try:
            box["r"] = fn()
        except BaseException as e:  # noqa: BLE001 — передаём наружу
            box["e"] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if "e" in box:
        raise box["e"]
    if "r" not in box:
        raise TimeoutError("timeout")
    return box["r"]


def resolve4(host):
    if host in OPT.resolve:
        return [OPT.resolve[host]]
    infos = in_thread(lambda: socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM), OPT.timeout)
    out = []
    for i in infos:
        if i[4][0] not in out:
            out.append(i[4][0])
    return out


def tls_connect(ip, sni, alpn, verify, min13=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if min13:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if verify:
        ctx.check_hostname, ctx.verify_mode = True, ssl.CERT_REQUIRED
        if OPT.cafile:
            ctx.load_verify_locations(OPT.cafile)
        else:
            ctx.load_default_certs()
    else:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    raw = socket.create_connection((ip, OPT.port), timeout=OPT.timeout)
    try:
        t0 = time.monotonic()
        s = ctx.wrap_socket(raw, server_hostname=sni)
        return s, (time.monotonic() - t0) * 1000
    except BaseException:
        raw.close()
        raise


def net_reason(e):
    if isinstance(e, ConnectionRefusedError):
        return f"порт {OPT.port} закрыт (соединение отклонено)"
    if isinstance(e, (socket.timeout, TimeoutError)):
        return f"нет ответа на порт {OPT.port} (таймаут {OPT.timeout:g} с)"
    if isinstance(e, ssl.SSLCertVerificationError):
        m = e.verify_message or str(e)
        if "Hostname mismatch" in m or "IP address mismatch" in m:
            return "сертификат выдан на другое имя"
        if "expired" in m:
            return "сертификат просрочен"
        if "self-signed" in m or "self signed" in m:
            return "самоподписанный сертификат"
        if "issuer" in m:
            return "сертификат не подтверждается доверенными центрами (CA)"
        return f"сертификат не прошёл проверку: {m}"
    if isinstance(e, ssl.SSLError):
        s = str(e).upper()
        if "PROTOCOL_VERSION" in s or "UNSUPPORTED_PROTOCOL" in s or "WRONG_VERSION" in s or "NO_PROTOCOLS" in s:
            return "сервер не поддерживает TLS 1.3"
        return f"ошибка TLS: {e.reason or e}"
    if isinstance(e, OSError):
        return f"сетевая ошибка: {e.strerror or e}"
    return f"ошибка: {e}"


def check_x25519(ip, sni):
    """True/False — поддерживает ли X25519 в TLS 1.3; None — не удалось проверить."""
    exe = shutil.which("openssl")
    if not exe:
        return None
    try:
        p = subprocess.run([exe, "s_client", "-connect", f"{ip}:{OPT.port}", "-servername", sni,
                            "-tls1_3", "-groups", "X25519", "-alpn", "h2"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=OPT.timeout + 2)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = p.stdout + p.stderr
    # OpenSSL 1.1/3.0/3.1: "Server Temp Key: X25519"; 3.2+: "Peer Temp Key"/"Negotiated TLS1.3 group: X25519".
    # Группа задана единственной, так что её появление в выводе и есть ответ; код возврата не важен
    # (сервер мог просто закрыть соединение сразу после рукопожатия).
    return bool(re.search(r"(?:Temp Key|TLS1\.3 group):\s*X25519", out))


def http_get(ip, host):
    """GET / по HTTP/1.1 поверх TLS. Возвращает (status, headers{lower: value}).
    Без ALPN: часть серверов на ALPN «только http/1.1» отвечает фатальным no_application_protocol."""
    s, _ = tls_connect(ip, host, None, verify=False, min13=False)
    with s:
        s.settimeout(OPT.timeout)
        s.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
                   "Gecko/20100101 Firefox/128.0\r\nAccept: text/html,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n"
                   "Connection: close\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            try:
                chunk = s.recv(8192)
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    if not m:
        raise ValueError("не HTTP-ответ")
    hdr = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdr.setdefault(k.strip().lower(), v.strip())
    return int(m.group(1)), hdr


def check(domain, neighbor_ips=None):
    """neighbor_ips — адреса соседей, в чьих сертификатах найдено это имя (тогда правила строже)."""
    d = domain.strip().lower().rstrip(".")
    r = {"domain": d, "ip": None, "verdict": OK, "reasons": [], "notes": [], "latency_ms": None, "tls13": None,
         "alpn": None, "cert_ok": None, "x25519": None, "http_status": None, "cdn": None,
         "registered": None, "age_days": None, "country": None, "server_country": OPT.server_country,
         "geoblock_ru": False}

    def bad(level, msg):
        r["reasons"].append(msg)
        r["verdict"] = max(r["verdict"], level)

    def done():
        r["verdict_name"] = VNAME[r["verdict"]]
        return r

    if d.startswith(("http://", "https://")):
        d = urlsplit(d).hostname or ""
    if d and not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    r["domain"] = d
    if not HOST_RE.match(d):
        bad(FAIL, "некорректное доменное имя (нужно вида www.example.de, без IP и пути)")
        return done()
    # репутация имени — офлайн, до любых соединений
    tld = d.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        bad(FAIL, f"дешёвая зона .{tld} — такие домены массово регистрируют под фишинг и чужие прокси")
        return done()
    if ru_segment(d) and OPT.server_country != "RU":
        bad(FAIL, "российский сайт на зарубежном сервере выглядит неестественно и попадает под особый контроль ТСПУ")
        return done()
    try:
        ips = resolve4(d)
    except (OSError, TimeoutError):
        ips = []
    if not ips:
        bad(FAIL, "нет DNS A-записи (домен не резолвится в IPv4)")
        return done()
    ip = r["ip"] = ips[0]
    if neighbor_ips:
        hit = [a for a in neighbor_ips if a in ips]
        if not hit:
            bad(FAIL, f"сосед {neighbor_ips[0]} выдаёт чужой сертификат (домен указывает на другой IP: "
                      f"{', '.join(ips[:2])}) — скорее всего это чужой VPN/прокси")
            return done()
        ip = r["ip"] = hit[0]
    for a in ips:
        c = cdn_of(a)
        if c:
            r["cdn"] = c
            bad(FAIL, f"сайт за CDN {c} ({a}) — общий IP, маскировка под него плохая")
            return done()
    o = overused(d)
    if o:
        bad(WARN, f"слишком популярное для маскировки имя («{o}») — его используют многие VPN")

    # 1) честное рукопожатие: TLS 1.3 + h2 + проверка сертификата на это имя
    sock = None
    try:
        sock, hs = tls_connect(ip, d, ["h2"], verify=True)
        r["cert_ok"] = True
    except ssl.SSLCertVerificationError as e:
        r["cert_ok"] = False
        bad(FAIL, net_reason(e))
        try:  # узнать остальное без проверки сертификата
            sock, hs = tls_connect(ip, d, ["h2"], verify=False)
        except (OSError, ssl.SSLError) as e2:
            bad(FAIL, net_reason(e2))
            return done()
    except (OSError, ssl.SSLError) as e:
        if isinstance(e, ssl.SSLError) and "TLS 1.3" in net_reason(e):
            r["tls13"] = False
        bad(FAIL, net_reason(e))
        return done()
    with sock:
        r["tls13"] = sock.version() == "TLSv1.3"
        r["alpn"] = sock.selected_alpn_protocol()
    r["latency_ms"] = round(hs)
    if not r["tls13"]:
        bad(FAIL, "сервер не поддерживает TLS 1.3")
    if r["alpn"] != "h2":
        bad(FAIL, "нет HTTP/2 (ALPN h2) — Reality с таким сайтом заметен")
    if hs > LATENCY_WARN_MS:
        bad(WARN, f"далеко от сервера: рукопожатие {round(hs)} мс (> {LATENCY_WARN_MS} мс)")

    # 2) X25519
    x = r["x25519"] = check_x25519(ip, d)
    if x is False:
        bad(FAIL, "сервер не поддерживает обмен ключами X25519")
    elif x is None:
        bad(WARN, "не удалось проверить X25519 (нет openssl или таймаут)")

    # 3) HTTP: живой ответ без ухода на чужой сайт, без признаков CDN в заголовках
    if not OPT.no_http:
        try:
            st, hdr = http_get(ip, d)
            r["http_status"] = st
            for k, pat, name in CDN_HEADERS:
                if k in hdr and re.search(pat, hdr[k], re.I):
                    r["cdn"] = name
                    bad(FAIL, f"ответ идёт через CDN {name} (заголовок {k})")
                    break
            if 300 <= st < 400:
                loc = hdr.get("location", "")
                u = urlsplit(loc)
                host = (u.hostname or "").lower()
                if not host:
                    pass
                elif u.scheme == "http":
                    bad(WARN, f"HTTP {st}: редирект на незашифрованный http://{host}")
                elif registrable(host) != registrable(d):
                    bad(FAIL, f"HTTP {st}: редиректит на другой сайт ({host}) — выберите конечный адрес")
                elif host != d:
                    bad(WARN, f"HTTP {st}: редирект на {host} — лучше указать сразу {host}")
            elif not 200 <= st < 300:
                bad(WARN, f"главная страница отвечает HTTP {st} (ожидался 2xx/3xx)")
        except (OSError, ssl.SSLError, ValueError) as e:
            bad(WARN, f"не удалось получить главную страницу ({net_reason(e) if isinstance(e, OSError) else e})")
    if r["verdict"] == FAIL:
        return done()

    # 4) возраст домена (RDAP) — только для прошедших технические проверки, чтобы беречь бюджет
    reg = domain_registered(d)
    if reg:
        age = (datetime.date.today() - reg).days
        r["registered"], r["age_days"] = reg.isoformat(), age
        if age < AGE_FAIL_DAYS:
            bad(FAIL, f"домен зарегистрирован {reg.isoformat()} (моложе 2 лет) — одноразовые домены "
                      "часто принадлежат мошенникам или чужим VPN")
            return done()
        if age < AGE_NOTE_DAYS:
            r["notes"].append(f"домену ~{age // 365} г.")
    elif neighbor_ips:
        bad(WARN, "возраст домена не удалось проверить (имя взято у соседа)")
    else:
        r["notes"].append("возраст домена не удалось проверить")

    # 5) география (мягко): страна IP сайта против страны сервера
    if OPT.server_country:
        cc = r["country"] = ip_country(ip)
        if cc and cc != OPT.server_country:
            r["notes"].append(f"сайт в {cc}, сервер в {OPT.server_country}")
    if geoblocks_ru(d):
        r["geoblock_ru"] = True
        r["notes"].append("блок РФ: не открывается из РФ (Reality не мешает, но менее естественно)")
    return done()


def summary(r):
    notes = "; ".join(r.get("notes") or [])
    if r["reasons"]:
        s = r["reasons"][0] + (f" (+{len(r['reasons']) - 1})" if len(r["reasons"]) > 1 else "")
    else:
        s = " ".join(["TLS1.3", "h2", "X25519"] + ([f"HTTP {r['http_status']}"] if r.get("http_status") else []))
    return f"{s}; {notes}" if notes else s


def print_check(r, out=sys.stdout):
    lat = f", {r['latency_ms']} мс" if r["latency_ms"] is not None else ""
    print(f"{r['domain']}: {r['verdict_name']}  (IP {r['ip'] or '—'}{lat})", file=out)
    for m in r["reasons"] or ["все проверки пройдены: TLS 1.3, h2, X25519, сертификат, HTTP"]:
        print(f"  - {m}", file=out)
    for m in r.get("notes") or []:
        print(f"  · примечание: {m}", file=out)


# ---------- сканирование ----------

def parallel(fn, items, workers, deadline):
    """Параллельно fn(item) на daemon-потоках с жёстким дедлайном. Возвращает {index: result}."""
    q, res, lock = queue.Queue(), {}, threading.Lock()
    for i, it in enumerate(items):
        q.put((i, it))

    def worker():
        while time.monotonic() < deadline:
            try:
                i, it = q.get_nowait()
            except queue.Empty:
                return
            try:
                v = fn(it)
            except Exception as e:  # noqa: BLE001
                v = e
            with lock:
                res[i] = v
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, min(workers, len(items))))]
    for t in ts:
        t.start()
    for t in ts:
        t.join(max(0.0, deadline - time.monotonic()))
    with lock:
        return dict(res)


def cert_names(der):
    """CN + SAN DNS-имена из DER без проверки (через openssl x509)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    exe = shutil.which("openssl")
    names = []
    if exe:
        try:
            p = subprocess.run([exe, "x509", "-noout", "-subject", "-ext", "subjectAltName", "-nameopt", "multiline"],
                               input=pem, capture_output=True, text=True, timeout=5)
            names += re.findall(r"commonName\s*=\s*(\S+)", p.stdout)
            names += re.findall(r"DNS:([^,\s]+)", p.stdout)
        except (subprocess.TimeoutExpired, OSError):
            pass
    else:  # запасной путь: внутренний декодер CPython
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
        try:
            c = ssl._ssl._test_decode_cert(f.name)  # type: ignore[attr-defined]
            names += [v for rdn in c.get("subject", ()) for k, v in rdn if k == "commonName"]
            names += [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
        except Exception:  # noqa: BLE001
            pass
        finally:
            os.unlink(f.name)
    out = []
    for n in names:
        n = n.lower().rstrip(".")
        if n.startswith("*."):
            # wildcard в SNI не подставить; пробуем конкретное www.<база> — в scan оно пройдёт, только
            # если резолвится в IP этого же соседа
            n = "www." + n[2:]
        if HOST_RE.match(n) and n not in out:
            out.append(n)
    return out


def probe_neighbor(ip):
    """TLS 1.3 + h2 без проверки сертификата → имена из сертификата (как RealiTLScanner)."""
    try:
        s, _ = tls_connect(ip, None, ["h2"], verify=False)
    except (OSError, ssl.SSLError, ValueError):
        return ip, []
    with s:
        if s.version() != "TLSv1.3" or s.selected_alpn_protocol() != "h2":
            return ip, []
        der = s.getpeercert(binary_form=True)
    return ip, (cert_names(der) if der else [])


def neighbor_hosts(server_ip):
    a = ipaddress.ip_address(server_ip)
    if a.version != 4:
        raise ValueError("нужен IPv4")
    if (a.is_private or a.is_reserved or a.is_link_local) and not a.is_loopback:
        raise ValueError(f"{server_ip} — не публичный адрес, соседей сканировать бессмысленно")
    net = ipaddress.ip_network(f"{server_ip}/24", strict=False)
    return [str(h) for h in net.hosts() if h != a]


def rank_key(r):
    """Порядок в рейтинге: годные выше FAIL; свои/курируемые выше соседей; OK выше WARN;
    сайты с блоком РФ ниже; дальше по задержке."""
    lat = r["latency_ms"] if r.get("latency_ms") is not None else 10 ** 6
    return (1 if r["verdict"] == FAIL else 0, 1 if r.get("neighbor") else 0, r["verdict"],
            1 if r.get("geoblock_ru") else 0, lat, r["domain"])


def visible(r):
    """Строка попадает в таблицу: не FAIL; сосед — только с полностью чистым OK."""
    return r["verdict"] != FAIL and (not r.get("neighbor") or r["verdict"] == OK)


def scan(neighbors=None, candidates=None, quiet=False):
    t_start = time.monotonic()
    say = (lambda *_: None) if quiet else log
    jobs = []  # (domain, source, neighbor_ips|None)
    cand = candidates if candidates is not None else CANDIDATES
    for d, cc in cand:  # курируемое/своё имя важнее «найденного у соседа»
        if all(d != j[0] for j in jobs):
            jobs.append((d, cc, None))
    if neighbors:
        try:
            hosts = neighbor_hosts(neighbors)
        except ValueError as e:
            say(f"соседи: пропускаю — {e}")
            hosts = []
        if hosts:
            say(f"сканирую соседей {neighbors}/24 на порту {OPT.port} ({len(hosts)} адресов, до 30 с)…")
            pr = parallel(probe_neighbor, hosts, 64, time.monotonic() + 30)
            found, seen = 0, {}
            for v in sorted((v for v in pr.values() if isinstance(v, tuple)), key=lambda v: ipaddress.ip_address(v[0])):
                if v[1]:
                    found += 1
                    for n in v[1][:4]:
                        seen.setdefault(n, []).append(v[0])
            known = {j[0] for j in jobs}
            nn = [(n, f"сосед {ips[0]}", ips) for n, ips in seen.items() if n not in known]
            jobs += nn
            say(f"соседи: TLS1.3+h2 отвечают {found}, имён для проверки {len(nn)} "
                "(годны, только если имя резолвится в IP соседа)")
    if OPT.server_country:
        say(f"страна сервера: {OPT.server_country}")
    say(f"проверяю {len(jobs)} сайтов (до 60 с)…")
    res = parallel(lambda j: check(j[0], j[2]), jobs, 16, time.monotonic() + 60)
    rows = []
    for i, (d, src, nips) in enumerate(jobs):
        r = res.get(i)
        if not isinstance(r, dict):
            r = {"domain": d, "ip": None, "verdict": FAIL, "verdict_name": "FAIL", "latency_ms": None, "notes": [],
                 "reasons": ["проверка не уложилась во время" if r is None else f"ошибка проверки: {r}"]}
        r["source"] = src
        r["neighbor"] = nips is not None
        rows.append(r)
    rows.sort(key=rank_key)
    say(f"готово за {time.monotonic() - t_start:.0f} с")
    return rows


LEGEND = ("  Сайт маскировки открывает сервер, а не браузер пользователя: если сайт не пускает посетителей из РФ\n"
          "  («блок РФ»), Reality это не ломает, но для пользователей из РФ естественнее доступные им сайты —\n"
          "  такие стоят выше. Соседи по /24 — только с подтверждённым DNS, ниже списка и не по умолчанию.")


def print_table(rows, limit, out):
    shown = [r for r in rows if visible(r)][:limit]
    failed = sorted((r for r in rows if not visible(r)), key=lambda r: -r["verdict"])  # сначала FAIL
    if shown:
        print(LEGEND, file=out)
        w = max(len(r["domain"]) for r in shown)
        ws = max(6, max(len(r["source"]) for r in shown))
        print(f"  {'#':>2}  {'домен'.ljust(w)}  {'откуда'.ljust(ws)}  итог  {'мс':>4}  примечание", file=out)
        for i, r in enumerate(shown, 1):
            lat = str(r["latency_ms"]) if r["latency_ms"] is not None else "—"
            print(f"  {i:>2}  {r['domain'].ljust(w)}  {r['source'].ljust(ws)}  {r['verdict_name']:<4}  {lat:>4}  "
                  f"{summary(r)}", file=out)
    else:
        print("  подходящих сайтов не найдено", file=out)
    if failed:
        print(f"  отброшено {len(failed)}: " + ", ".join(f"{r['domain']} ({r['reasons'][0]})" for r in failed[:6])
              + (" …" if len(failed) > 6 else ""), file=out)
    return shown


# ---------- выбор ----------

def open_tty():
    """(чтение, запись) для /dev/tty или None. Раздельные дескрипторы: tty не seekable, "r+" падает."""
    try:
        tin = open("/dev/tty", "r", encoding="utf-8", errors="replace")
        tout = open("/dev/tty", "w", encoding="utf-8", errors="replace", buffering=1)
        return tin, tout
    except OSError:
        return None


def pick(args):
    tty = None if args.non_interactive else open_tty()
    tin, tty = tty if tty else (None, None)
    cur = None
    if args.default:
        cur = check(args.default)
    rows = scan(args.neighbors, args.cand, quiet=False)
    if cur:
        rows = [r for r in rows if r["domain"] != cur["domain"]]
        cur["source"], cur["neighbor"] = "текущий", False
    if tty is None:
        if cur and cur["verdict"] == OK:
            print(cur["domain"])
            return 0
        best = next((r for r in rows if r["verdict"] == OK and not r["neighbor"]), None)  # сосед — никогда
        print_table(rows, args.limit, sys.stderr)
        if not best:
            log("нет ни одного сайта из списка с итогом OK — укажите домен вручную (SNI=...)")
            return 2
        log(f"выбран автоматически: {best['domain']}")
        print(best["domain"])
        return 0

    def say(msg=""):
        tty.write(msg + "\n")
        tty.flush()

    def ask(q):
        tty.write(q)
        tty.flush()
        ln = tin.readline()
        if not ln:
            raise EOFError
        return ln.strip()

    if cur and cur["verdict"] == WARN:  # текущий с замечаниями — на общих основаниях
        rows = sorted(rows + [cur], key=rank_key)
    shown = print_table(([cur] if cur and cur["verdict"] == OK else []) + rows, args.limit, tty)
    if cur and cur["verdict"] == FAIL:
        say(f"текущий {cur['domain']} больше не подходит: {'; '.join(cur['reasons'])}")
    dflt = next((r for r in shown if not r["neighbor"]), None)  # Enter никогда не выбирает соседа
    try:
        while True:
            hint = f"Enter = {dflt['domain']}" if dflt else "введите домен"
            a = ask(f"Номер из списка, свой домен или Enter [{hint}]: ")
            if not a:
                if not dflt:
                    say("список пуст — введите домен сайта")
                    continue
                r = dflt
            elif a.isdigit():
                n = int(a)
                if not 1 <= n <= len(shown):
                    say(f"нет номера {n}; допустимо 1–{len(shown)}")
                    continue
                r = shown[n - 1]
            else:
                say(f"проверяю {a}…")
                r = check(a)
                print_check(r, tty)
            if r["verdict"] == FAIL:
                say("этот сайт не подходит, выберите другой")
                continue
            if r["verdict"] == WARN:
                if ask(f"{r['domain']}: есть замечания ({'; '.join(r['reasons'])}). Использовать? [y/N]: ").lower() \
                        not in ("y", "yes", "д", "да"):
                    continue
            say(f"выбран: {r['domain']}")
            print(r["domain"])
            return 0
    except EOFError:
        say("\nввод прерван")
        return 2


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--resolve", action="append", default=[], metavar="DOMAIN:IP")
    common.add_argument("--port", type=int, default=443)
    common.add_argument("--cafile")
    common.add_argument("--no-http", action="store_true")
    common.add_argument("--timeout", type=float, default=4.0)
    common.add_argument("--json", action="store_true")
    common.add_argument("--candidates", help="через запятую, вместо встроенного списка")
    common.add_argument("--server-country", metavar="CC", help="страна сервера (иначе по RDAP для --neighbors)")
    common.add_argument("--rdap-offline", action="store_true", help="не обращаться к RDAP")
    p = argparse.ArgumentParser(prog="sni.py", description="Подбор сайта маскировки для Xray REALITY")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", parents=[common])
    c.add_argument("domain")
    for name in ("scan", "pick"):
        s = sub.add_parser(name, parents=[common])
        s.add_argument("--neighbors", metavar="SERVER_IP")
        s.add_argument("--limit", type=int, default=15)
        if name == "pick":
            s.add_argument("--default")
            s.add_argument("--non-interactive", action="store_true")
    a = p.parse_args(argv)
    for item in a.resolve:
        dom, _, ip = item.rpartition(":")
        if not dom or not ip:
            p.error(f"--resolve ожидает DOMAIN:IP, получено {item!r}")
        OPT.resolve[dom.lower()] = ip
    OPT.port, OPT.cafile, OPT.no_http, OPT.timeout = a.port, a.cafile, a.no_http, a.timeout
    OPT.rdap_offline = a.rdap_offline
    if a.server_country:
        if not re.fullmatch(r"[A-Za-z]{2}", a.server_country):
            p.error("--server-country ожидает двухбуквенный код страны, например DE")
        OPT.server_country = a.server_country.upper()
    elif getattr(a, "neighbors", None):
        try:
            ipaddress.ip_address(a.neighbors)
            OPT.server_country = ip_country(a.neighbors)
        except ValueError:
            pass
    a.cand = None
    if a.candidates is not None:
        a.cand = [(d.strip().lower(), "свой список") for d in a.candidates.split(",") if d.strip()]

    if a.cmd == "check":
        r = check(a.domain)
        if a.json:
            print(json.dumps(r, ensure_ascii=False, indent=2))
        else:
            print_check(r)
        return r["verdict"]
    if a.cmd == "scan":
        rows = scan(a.neighbors, a.cand, quiet=a.json)
        if a.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        else:
            print_table(rows, a.limit, sys.stdout)
        return min((r["verdict"] for r in rows), default=FAIL)
    return pick(a)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\nпрервано")
        sys.exit(130)
PYEOF
  chmod 600 "$STATE/provision.py" "$STATE/sni.py"
}
run_provision(){ # доп. переменные окружения передаются через env перед вызовом
  PANEL_URL="http://127.0.0.1:${P_PORT}/${P_PATH}" TOKEN_FILE="$STATE/api.token" STATE_DIR="$STATE/keys" \
  XRAY_BIN="$XRAY_BIN" PUBLIC_IP="$PUBLIC_IP" USERS="$USERS" SNI="$SNI" FLAG="$(flag_of "${COUNTRY:-}")" \
  PORT_REALITY="$PORT_REALITY" PORT_SUDOKU="$PORT_SUDOKU" PORT_XHTTP="$PORT_XHTTP" \
    python3 -I "$STATE/provision.py"
}
publish_links(){
  cp "$STATE/keys/links.txt" "$STATE/links.txt"; chmod 600 "$STATE/links.txt"
  ops_links >/dev/null
}
# ---------- обновление 3X-UI с точкой отката ----------
ver_gt(){ [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" = "$1" ]; }
xui_snapshot(){ # «теги inbound | число клиентов» прямо из базы (не зависит от API)
  local t c
  t=$(sqlite3 -readonly /etc/x-ui/x-ui.db "select tag from inbounds order by tag" 2>/dev/null | paste -sd, -) || true
  c=$(sqlite3 -readonly /etc/x-ui/x-ui.db "select count(*) from clients" 2>/dev/null) || true
  echo "${t}|${c:-?}"
}
xui_install_files(){ # xui_install_files КАТАЛОГ_С_x-ui — разложить файлы панели
  rm -rf /usr/local/x-ui && cp -a "$1" /usr/local/x-ui
  chmod +x /usr/local/x-ui/x-ui "$XRAY_BIN" /usr/local/x-ui/x-ui.sh
  install -m 755 /usr/local/x-ui/x-ui.sh /usr/bin/x-ui
  install -m 644 /usr/local/x-ui/x-ui.service.debian /etc/systemd/system/x-ui.service
  install -d /var/log/x-ui
  systemctl daemon-reload
}
xui_upgrade_prepare(){ # xui_upgrade_prepare СТАРАЯ_ВЕРСИЯ — бэкап + копия для отката, панель остановлена
  XUI_RB="$STATE/rollback-$1"
  echo "Обновляю панель 3X-UI: $1 → ${XUI_VERSION#v}."
  echo "Сначала бэкап и точка отката: если новая версия не заработает, всё вернётся как было (VPN пропадёт на ~1 мин)."
  ops_backup
  xui_stop_wait
  XUI_SNAP=$(xui_snapshot)
  rm -rf "$STATE"/rollback-*; install -d -m 700 "$XUI_RB"
  cp -a /usr/local/x-ui "$XUI_RB/x-ui" && cp -a /etc/x-ui "$XUI_RB/etc-x-ui" \
    && cp -a /etc/systemd/system/x-ui.service "$STATE/api.token" "$STATE/auth.hdr" "$XUI_RB/" \
    || { systemctl start x-ui 2>/dev/null || true; die "не удалось сохранить копию для отката — обновление отменено, панель не тронута"; }
  echo "точка отката: $XUI_RB"
}
xui_stop_wait(){ # остановить панель и дождаться, пока процессы панели и Xray завершатся
  local i
  systemctl stop x-ui 2>/dev/null || true
  for i in $(seq 1 20); do
    pgrep -x x-ui >/dev/null 2>&1 || pgrep -f "[x]ray-linux-${ARCH}" >/dev/null 2>&1 || return 0
    sleep 1
  done
  pkill -9 -x x-ui 2>/dev/null || true; pkill -9 -f "[x]ray-linux-${ARCH}" 2>/dev/null || true; sleep 1
}
xui_rollback(){ # xui_rollback ПРИЧИНА — вернуть старую версию и остановиться
  trap - ERR
  warn "новая версия 3X-UI не заработала: $1 — возвращаю прежнюю"
  journalctl -u x-ui -n 30 --no-pager 2>/dev/null | tail -n 30 >&2 || true
  xui_stop_wait
  if rm -rf /etc/x-ui && cp -a "$XUI_RB/etc-x-ui" /etc/x-ui && xui_install_files "$XUI_RB/x-ui" \
     && cp -a "$XUI_RB/x-ui.service" /etc/systemd/system/x-ui.service && systemctl daemon-reload \
     && cp -a "$XUI_RB/api.token" "$XUI_RB/auth.hdr" "$STATE/"; then
    systemctl restart x-ui 2>/dev/null || true
    die "обновление 3X-UI отменено, возвращена версия ${XUI_RB##*rollback-} — VPN работает как раньше.
  Ничего делать не нужно. Пришли эту ошибку и вывод выше — разберёмся."
  fi
  die "ОТКАТ НЕ УДАЛСЯ. Старая версия лежит в $XUI_RB, бэкап — в $STATE/backup.
  Ничего не удаляй и пришли весь вывод — восстановим вручную."
}
xui_upgrade_verify(){ # после старта новой версии: те же inbound и клиенты, Xray запущен
  local now i
  now=$(xui_snapshot)
  [ "$now" = "$XUI_SNAP" ] || xui_rollback "после обновления изменились inbound/клиенты (было: $XUI_SNAP, стало: $now)"
  for i in $(seq 1 20); do pgrep -f "[x]ray-linux-${ARCH}" >/dev/null 2>&1 && break; sleep 1; done
  pgrep -f "[x]ray-linux-${ARCH}" >/dev/null 2>&1 || xui_rollback "Xray не запустился"
  echo "обновление 3X-UI прошло: inbound и клиенты на месте, Xray работает (копия старой версии: $XUI_RB)"
}
detect_country(){ # двухбуквенный код страны IP сервера (DE, FR…); пусто, если не удалось
  local c=""
  c=$(curl -fsS --max-time 8 "https://ipinfo.io/${PUBLIC_IP}/country" 2>/dev/null | tr -dc 'A-Za-z') || true
  [ ${#c} = 2 ] || c=$(curl -fsS --max-time 8 "https://ipapi.co/${PUBLIC_IP}/country/" 2>/dev/null | tr -dc 'A-Za-z') || true
  [ ${#c} = 2 ] || c=$(curl -fsS --max-time 8 "https://rdap.org/ip/${PUBLIC_IP}" 2>/dev/null \
                        | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("country",""))' 2>/dev/null) || true
  c=$(printf '%s' "$c" | tr 'a-z' 'A-Z'); [ ${#c} = 2 ] && echo "$c"
  return 0
}
flag_of(){ # DE → 🇩🇪
  python3 -I -c 'import sys; c=sys.argv[1].upper(); print("".join(chr(0x1F1E6+ord(x)-65) for x in c) if len(c)==2 and c.isalpha() else "")' "${1:-}"
}
install_cli(){ # короткая команда vpn-setup и подсказка при входе на сервер
  [ -f "$STATE/install.sh" ] || return 0
  ln -sfn "$STATE/install.sh" /usr/local/bin/vpn-setup
  if [ -d /etc/update-motd.d ]; then
    cat > /etc/update-motd.d/90-vpn-setup <<'MOTD'
#!/bin/sh
[ -f /root/vpn-setup/config.env ] || exit 0
echo
echo " VPN-сервер (vpn-setup). Меню управления:  vpn-setup      (команды: vpn-setup help)"
[ -f /etc/ssh/sshd_config.d/00-hardening.conf ] || echo " ! Вход по паролю включён. Когда войдёшь по ключу:  vpn-setup harden-ssh"
[ -f /var/run/reboot-required ] && echo " ! Ожидают перезагрузки обновления безопасности:  reboot  (VPN пропадёт на 1–2 мин)"
exit 0
MOTD
    chmod 755 /etc/update-motd.d/90-vpn-setup
  fi
}
detect_public_ip(){
  local ip=""
  ip=$(curl -4 -fsS --max-time 10 https://ifconfig.co 2>/dev/null || curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null) || true
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}') || true
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  echo "$ip"
}
check_sni(){ # check_sni DOMAIN — проверка; SNI_SKIP_CHECK=1 — довериться пользователю
  local rc=0
  if [ "${SNI_SKIP_CHECK:-0}" = 1 ]; then warn "проверка сайта $1 пропущена по SNI_SKIP_CHECK=1"; return 0; fi
  python3 -I "$STATE/sni.py" check ${COUNTRY:+--server-country "$COUNTRY"} "$1" >&2 || rc=$?
  case $rc in
    0) return 0 ;;
    1) warn "$1 прошёл с замечаниями (выше) — использую" ;;
    *) die "сайт $1 не подходит для маскировки (причины выше). Другой: SNI=домен, или без проверки: SNI_SKIP_CHECK=1" ;;
  esac
}
choose_sni(){ # choose_sni [ЯВНЫЙ_ДОМЕН] — печатает выбранный домен
  local d="${1:-}"
  if [ -n "$d" ]; then check_sni "$d"; echo "$d"; return 0; fi
  d=$(python3 -I "$STATE/sni.py" pick --neighbors "$PUBLIC_IP" ${COUNTRY:+--server-country "$COUNTRY"} ${SNI:+--default "$SNI"} | tail -n 1) || true
  [ -n "$d" ] || die "не удалось подобрать сайт маскировки. Задай вручную: SNI=www.example.de bash install.sh"
  echo "$d"
}

# ===================== подкоманды =====================
panel_text(){ # инструкция по входу в панель через SSH-туннель с реальными значениями
  local ip="${PUBLIC_IP:-IP_СЕРВЕРА}" sp
  sp=$(detect_ssh_ports | awk '{print $1}') || true; sp=${sp:-22}
  cat <<PANEL
ПАНЕЛЬ 3X-UI. Снаружи она закрыта — это защита. Заходить только через SSH-туннель:
туннель «пробрасывает» порт ${P_PORT} с сервера на твой компьютер, и панель открывается как локальная.

Адрес в браузере (пока туннель включён):  http://127.0.0.1:${P_PORT}/${P_PATH}/
Логин: ${P_USER}    Пароль: ${P_PASS}

Как включить туннель — выбери один вариант:

1) Windows / macOS / Linux — одна команда в терминале (PowerShell, Terminal):
     ssh -N -L ${P_PORT}:127.0.0.1:${P_PORT} root@${ip} -p ${sp}
   Окно не закрывай, пока работаешь с панелью. Остановить — Ctrl+C.
   (Windows: если «ssh не найден» — Параметры → Приложения → Дополнительные компоненты → «Клиент OpenSSH».)

2) MobaXterm (Windows):
   Tunneling → New SSH tunnel → Local port forwarding;
   My computer: порт ${P_PORT};  SSH server: ${ip}, пользователь root, порт ${sp} (+ значок ключа, если вход по ключу);
   Remote server: 127.0.0.1, порт ${P_PORT}  →  Save → ▶ Start.

3) PuTTY (Windows): Connection → SSH → Tunnels: Source port ${P_PORT}, Destination 127.0.0.1:${P_PORT}, Local → Add;
   затем Session: ${ip}, порт ${sp} → Open и войди.

4) Телефон — Termius (Android/iOS): Port Forwarding → New → Local; Local port ${P_PORT},
   Host: этот сервер, Destination 127.0.0.1:${P_PORT} → подключиться, затем в браузере телефона адрес выше.

Не работает? 1) туннель запущен и не закрыт; 2) адрес именно 127.0.0.1, порт ${P_PORT}, путь /${P_PATH}/;
3) VPN-клиент в режиме TUN может перехватывать SSH — выключи его или добавь IP сервера в исключения.
PANEL
}
cmd_panel(){ require_installed; load_config; panel_text; }
cmd_update(){ # скачать свежий скрипт с GitHub (main) и запустить повторную установку — данные сохраняются
  local new="$STATE/install.sh.new" url="${SELF_URL%/*/install.sh}/main/install.sh" v
  require_installed
  echo "Скачиваю свежую версию: $url"
  curl -fsSL --retry 2 --connect-timeout 15 -o "$new" "$url" || { rm -f "$new"; die "не удалось скачать скрипт с GitHub — проверь интернет на сервере и повтори"; }
  bash -n "$new" && grep -q '^SCRIPT_VERSION="v' "$new" || { rm -f "$new"; die "скачанный файл повреждён или это не vpn-setup — ничего не изменено"; }
  v=$(sed -n 's/^SCRIPT_VERSION="\(.*\)"$/\1/p' "$new" | head -n 1) || true
  mv "$new" "$STATE/install.sh"; chmod 700 "$STATE/install.sh"
  echo "Было: ${SCRIPT_VERSION}, стало: ${v:-?}. Запускаю обновление (пользователи и ссылки сохраняются)…"
  VPN_SETUP_REEXEC=1 exec bash "$STATE/install.sh" install
}

cmd_precheck(){ # проверка ДО установки: доходят ли данные с домашнего ПК до этого IP
  [ "$(id -u)" = 0 ] || die "нужен root"
  local port="${1:-8080}" dir ip opened=0 busy
  [[ "$port" =~ ^[0-9]+$ ]] || die "порт должен быть числом"
  busy=$(ss -Htln "sport = :$port" 2>/dev/null) || true
  [ -z "$busy" ] || die "порт $port занят — укажи другой: bash install.sh precheck 8090"
  dir=$(mktemp -d); head -c 300000 /dev/urandom > "$dir/f.bin"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -c '^Status: active' >/dev/null; then
    ufw allow "$port/tcp" comment 'vpn-setup precheck' >/dev/null && opened=1
  fi
  ip=$(detect_public_ip || true)
  echo -e "${c_ok}Тестовый сервер запущен на 3 минуты (порт $port).${c_no}"
  echo "С ДОМАШНЕГО ПК, VPN ВЫКЛЮЧЕН, выполни (MobaXterm → local terminal):"
  echo "   bash check-server.sh ${ip:-IP_СЕРВЕРА} $port"
  echo "или вручную:"
  echo "   curl -s -o /dev/null --max-time 20 -w \"bytes=%{size_download}\\n\" http://${ip:-IP_СЕРВЕРА}:$port/f.bin"
  echo "Ожидается bytes=300000. Ниже будут видны пришедшие запросы. Остановить раньше: Ctrl+C"
  trap ':' INT   # Ctrl+C останавливает только тестовый сервер, уборка ниже выполнится
  ( cd "$dir" && timeout --foreground 180 python3 -m http.server "$port" --bind 0.0.0.0 ) || true
  trap - INT
  rm -rf "$dir"
  [ "$opened" = 1 ] && { ufw delete allow "$port/tcp" >/dev/null 2>&1 || true; }
  echo "Тестовый сервер остановлен$([ "$opened" = 1 ] && echo ', порт закрыт')."
  echo "Если на ПК было bytes=300000 — ставь:  bash install.sh   Если 0 — этот IP твой провайдер режет, ставить бессмысленно."
}

cmd_sni(){
  require_installed; load_config
  local new="${1:-}"
  [ -z "${DOMAIN:-}" ] || die "сейчас включён свой домен ($DOMAIN). Вернуться к чужому сайту: vpn-setup domain off"
  write_helpers
  PUBLIC_IP=${PUBLIC_IP:-$(detect_public_ip || true)}
  step "Смена сайта маскировки Reality (сейчас: ${SNI:-не задан})"
  SNI=$(choose_sni "$new") || exit 1
  echo "Выбрано: $SNI"
  SET_SNI="$SNI" run_provision
  save_config; publish_links
  warn "Ссылки и QR профиля Reality изменились: раздай пользователям новые (vpn-setup links)."
}

choose_site_template(){ # шаблон сайта-заглушки (из модуля сайтов); Enter — первый. Пишет SITE_TEMPLATE
  declare -F domain_site_list >/dev/null || return 0
  [ -z "${SITE_TEMPLATE:-}" ] || return 0
  local list="" ans="" ids n
  list=$(domain_site_list 2>/dev/null | awk 'NF') || true
  [ -n "$list" ] || return 0
  ids=$(printf '%s\n' "$list" | awk -F'|' '{print $1}')
  if (: </dev/tty) 2>/dev/null; then
    echo "Какой сайт показывать на домене всем «чужим» (потом можно сменить: vpn-setup site, или заменить своими файлами):"
    printf '%s\n' "$list" | awk -F'|' '{printf "  %d) %s — %s\n", NR, $2, $3}'
    ask ans "Номер шаблона" "1"
  fi
  ans=${ans:-1}
  if [[ "$ans" =~ ^[0-9]+$ ]]; then n=$ans; SITE_TEMPLATE=$(printf '%s\n' "$ids" | sed -n "${n}p")
  elif printf '%s\n' "$ids" | grep -qx -- "$ans"; then SITE_TEMPLATE="$ans"; fi
  [ -n "${SITE_TEMPLATE:-}" ] || SITE_TEMPLATE=$(printf '%s\n' "$ids" | sed -n 1p)
  echo "сайт-заглушка: $SITE_TEMPLATE"
}
domain_fail_cleanup(){ # EXIT-ловушка cmd_domain: при ошибке вернуть сервер как было
  local rc=$?
  [ "$rc" = 0 ] && return 0
  if [ -n "${DOMAIN_FAIL_HAD:-}" ]; then  # переключались с другого своего домена — вернуть его сайт в nginx
    ( DOMAIN_SKIP_DNS=1 domain_setup "$DOMAIN_FAIL_HAD" "${PUBLIC_IP:-}" ) >/dev/null 2>&1 \
      || warn "не удалось вернуть сайт $DOMAIN_FAIL_HAD — выполни: vpn-setup domain $DOMAIN_FAIL_HAD"
  else domain_disable >/dev/null 2>&1 || true; fi
  echo -e "${c_warn}! свой домен не подключён (причина выше). VPN работает как раньше, маскировка: ${DOMAIN_FAIL_SNI:-?}${c_no}" >&2
  exit "$rc"
}
cmd_domain(){ # vpn-setup domain ДОМЕН | off | (без аргумента — состояние)
  local env_tpl="${SITE_TEMPLATE:-}"
  require_installed; load_config
  [ -n "$env_tpl" ] && SITE_TEMPLATE="$env_tpl"
  local arg="${1:-}" d had=""
  write_helpers
  PUBLIC_IP=${PUBLIC_IP:-$(detect_public_ip || true)}
  [ -n "$PUBLIC_IP" ] || die "не удалось определить внешний IPv4. Задай: PUBLIC_IP=x.x.x.x vpn-setup domain …"
  case "$arg" in
    "")
      if [ -n "${DOMAIN:-}" ]; then echo "Свой домен: $DOMAIN (сайт: $DOMAIN_WWW_ROOT/$DOMAIN, Reality → 127.0.0.1:${DOMAIN_PORT:-?})"
      else echo "Свой домен не включён. Сейчас Reality маскируется под: ${SNI:-?}"; fi
      echo "Включить: vpn-setup domain example.com    Выключить: vpn-setup domain off"
      ;;
    off)
      [ -n "${DOMAIN:-}" ] || { echo "свой домен и так не включён (SNI: ${SNI:-?})"; return 0; }
      step "Выключаю свой домен $DOMAIN → обратно на чужой сайт маскировки"
      SNI=$(choose_sni "${BORROWED_SNI:-}") || exit 1
      SET_SNI="$SNI" run_provision
      domain_disable
      rm -f /etc/cron.d/vpn-setup-certbot
      DOMAIN=""; DOMAIN_PORT=""; echo "$SNI" > "$STATE/sni"
      save_config; publish_links
      warn "Ссылки и QR профиля Reality изменились: раздай пользователям новые (vpn-setup links)."
      ;;
    *)
      d=$(domain_normalize "$arg") || die "некорректное имя домена: $arg"
      step "Свой домен для Reality: $d"
      had="${DOMAIN:-}"
      [ -n "$had" ] || BORROWED_SNI="${SNI:-}"
      domain_name_check "$d"; domain_dns_check "$d" "$PUBLIC_IP"   # до любых изменений на сервере
      firewall_apply "$PORT_REALITY" "$PORT_SUDOKU" "$PORT_XHTTP" 80
      # если сайт не поднялся (любая ошибка → exit) — убрать наши следы (nginx-конфиг, порт 80); VPN остаётся как был
      DOMAIN_FAIL_SNI="${SNI:-?}" DOMAIN_FAIL_HAD="$had"
      trap 'domain_fail_cleanup' EXIT
      domain_setup "$d" "$PUBLIC_IP"
      ensure_cert_renewal
      SET_SNI="$d" REALITY_TARGET="127.0.0.1:$DOMAIN_PORT" run_provision
      trap - EXIT
      DOMAIN="$d"; SNI="$d"; echo "$SNI" > "$STATE/sni"
      save_config; publish_links
      if [ "${VPN_SETUP_QUIET_LINKS:-0}" != 1 ]; then
        warn "Ссылки и QR профиля Reality изменились: раздай пользователям новые (vpn-setup links)."
      fi
      echo "Сайт можно заменить своими файлами: $DOMAIN_WWW_ROOT/$d (vpn-setup его не перезапишет)."
      ;;
  esac
}

cmd_install(){
  step "0/9 Проверки"
  [ "$(id -u)" = 0 ] || die "запусти от root"
  # shellcheck disable=SC1091
  . /etc/os-release
  [ "${ID:-}" = ubuntu ] || die "поддерживается только Ubuntu 22.04/24.04/26.04 (обнаружено: ${PRETTY_NAME:-?})"
  case "${VERSION_ID:-}" in 22.04|24.04|26.04) ;; *) warn "Ubuntu ${VERSION_ID:-?} не проверялась — продолжаю на свой риск";; esac
  local ENV_SNI="${SNI:-}" ENV_USERS="${USERS:-}" ENV_COUNTRY_IN="${COUNTRY:-}" ENV_DOMAIN="${DOMAIN:-}" ENV_TPL="${SITE_TEMPLATE:-}"
  local FRESH=0; is_installed || FRESH=1
  load_config
  [ -n "$ENV_TPL" ] && SITE_TEMPLATE="$ENV_TPL"
  if [ -n "$ENV_USERS" ]; then  # объединяем с уже существующими — старых не теряем
    USERS=$(printf '%s\n' ${USERS:-} $ENV_USERS | awk 'NF && !seen[$0]++' | xargs)
  fi
  if [ -f /etc/x-ui/x-ui.db ] && [ ! -f "$STATE/panel.env" ]; then
    die "здесь уже стоит 3X-UI, установленный не этим скриптом. Чтобы не сломать его, установка остановлена.
  Скрипт рассчитан на чистый сервер. Если панель не нужна: 'x-ui uninstall', затем запусти снова."
  fi
  install -d -m 700 "$STATE"
  SSH_PORTS=$(detect_ssh_ports)
  local p busy
  for p in "$PORT_REALITY" "$PORT_SUDOKU" "$PORT_XHTTP"; do
    for s in $SSH_PORTS; do [ "$p" = "$s" ] && die "порт $p занят SSH — выбери другой: PORT_...=N bash install.sh"; done
    busy=$(ss -Htlnp "sport = :$p" 2>/dev/null | grep -v -e xray -e '^$') || true
    [ -z "$busy" ] || die "порт $p занят: $busy"
  done
  echo "Ubuntu ${VERSION_ID}, ${ARCH}, SSH: ${SSH_PORTS}"

  ask USERS "Имена пользователей латиницей через пробел" "${USERS:-HOME_PC}"
  for u in $USERS; do [[ "$u" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die "имя '$u': только латиница, цифры, _ и -"; done
  if [ ! -s /root/.ssh/authorized_keys ]; then
    ask SSH_PUBKEY "Публичный SSH-ключ (строка ssh-ed25519 AAAA… из MobaKeyGen, Enter — пропустить)" ""
  fi

  step "1/9 Обновление системы и пакеты"
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
  if command -v cloud-init >/dev/null 2>&1; then
    echo "жду завершения первичной настройки сервера (cloud-init)…"; timeout 600 cloud-init status --wait >/dev/null 2>&1 || true
  fi
  local APT=(apt-get -y -q -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  local n=0; until "${APT[@]}" update; do n=$((n+1)); [ "$n" -ge 4 ] && die "apt-get update не прошёл 4 раза (сеть/зеркала?)"; sleep $((n*15)); done
  "${APT[@]}" full-upgrade
  "${APT[@]}" install curl ca-certificates openssl python3 ufw fail2ban qrencode sqlite3 tar cron unattended-upgrades iproute2 >/dev/null
  echo "пакеты установлены, автообновления безопасности: $(systemctl is-enabled unattended-upgrades 2>/dev/null || echo '?')"

  step "2/9 SSH-ключ"
  if [ -n "${SSH_PUBKEY:-}" ]; then ssh_add_pubkey "$SSH_PUBKEY"; else echo "ключ не передан — пропускаю"; fi

  step "3/9 IPv6 off, BBR, swap"
  local IFACE
  IFACE=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}') || true
  [ -n "$IFACE" ] || die "не найден сетевой интерфейс с маршрутом по умолчанию"
  local V6="" CLIENT_IP; CLIENT_IP=$(ssh_client_ip)
  case "$CLIENT_IP" in
    *:*) warn "ты подключён по IPv6 ($CLIENT_IP) — IPv6 не отключаю, чтобы не потерять доступ" ;;
    *) V6="net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.${IFACE}.disable_ipv6 = 1" ;;
  esac
  cat > /etc/sysctl.d/90-vpn.conf <<EOF
# vpn-setup: IPv6 выключен (клиенты подключаются по IPv4), BBR для длинных каналов с потерями
${V6}
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
vm.swappiness = 10
EOF
  echo tcp_bbr > /etc/modules-load.d/bbr.conf
  modprobe tcp_bbr 2>/dev/null || true
  sysctl -q -p /etc/sysctl.d/90-vpn.conf || warn "часть sysctl не применилась (виртуализация?)"
  if [ -z "$(swapon --show --noheadings 2>/dev/null)" ] && [ "$(awk '/MemTotal/{print $2}' /proc/meminfo)" -lt 3000000 ] && [ ! -e /swapfile ]; then
    if fallocate -l 1G /swapfile 2>/dev/null && chmod 600 /swapfile && mkswap -q /swapfile && swapon /swapfile; then
      echo '/swapfile none swap sw 0 0' >> /etc/fstab; echo "swap 1G создан"
    else rm -f /swapfile; warn "swap создать не удалось (OpenVZ/LXC?) — продолжаю без него"; fi
  fi
  echo "интерфейс ${IFACE}: IPv6 $([ -n "$V6" ] && echo off || echo оставлен), $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')"

  step "4/9 3X-UI ${XUI_VERSION}"
  local XUI_CUR="" XUI_UPGRADED=0
  if [ -x /usr/local/x-ui/x-ui ]; then XUI_CUR=$(/usr/local/x-ui/x-ui -v 2>/dev/null | tr -dc '0-9.\n' | sed -n 1p) || true; fi
  if [ -n "$XUI_CUR" ] && ver_gt "$XUI_CUR" "${XUI_VERSION#v}"; then
    warn "3X-UI уже новее ($XUI_CUR), чем проверенная скриптом ${XUI_VERSION#v} — видимо, нажали «Обновить» в панели.
  Откатывать нельзя (база уже переделана под новую версию) — оставляю как есть. Проверь: vpn-setup status"
  elif [ "$XUI_CUR" != "${XUI_VERSION#v}" ]; then
    local TMP; TMP=$(mktemp -d)
    curl -fsSL --retry 3 --connect-timeout 15 -o "$TMP/x-ui.tgz" \
      "https://github.com/MHSanaei/3x-ui/releases/download/${XUI_VERSION}/x-ui-linux-${ARCH}.tar.gz" \
      || die "не удалось скачать 3X-UI с GitHub (доступ к github.com с сервера?)"
    echo "${XUI_SHA256[$ARCH]}  $TMP/x-ui.tgz" | sha256sum -c --quiet - || die "контрольная сумма архива не совпала — установка остановлена"
    echo "контрольная сумма совпала"
    tar xzf "$TMP/x-ui.tgz" -C "$TMP"
    if [ -n "$XUI_CUR" ] && [ -f /etc/x-ui/x-ui.db ] && [ -f "$STATE/panel.env" ]; then
      xui_upgrade_prepare "$XUI_CUR"; XUI_UPGRADED=1
    fi
    xui_stop_wait
    xui_install_files "$TMP/x-ui"; rm -rf "$TMP"
  fi
  "$XRAY_BIN" version 2>/dev/null | sed -n 1p
  if [ ! -f "$STATE/panel.env" ]; then
    P_USER="u$(openssl rand -hex 5)"; P_PASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)"
    P_PORT=$(( 20000 + $(od -An -N2 -tu2 /dev/urandom) % 40000 )); P_PATH="$(openssl rand -hex 8)"
    /usr/local/x-ui/x-ui setting -username "$P_USER" -password "$P_PASS" -port "$P_PORT" -webBasePath "$P_PATH" -listenIP 127.0.0.1 >/dev/null
    /usr/local/x-ui/x-ui migrate >/dev/null 2>&1 || true
    ( umask 077; printf 'P_USER=%q\nP_PASS=%q\nP_PORT=%q\nP_PATH=%q\n' "$P_USER" "$P_PASS" "$P_PORT" "$P_PATH" > "$STATE/panel.env" )
  fi
  # shellcheck disable=SC1091
  . "$STATE/panel.env"
  if [ "$XUI_UPGRADED" = 1 ]; then  # перенос базы на новую версию (один раз) — до старта службы
    /usr/local/x-ui/x-ui migrate >/dev/null 2>&1 || xui_rollback "не удалось перенести базу на новую версию"
  fi
  /usr/local/x-ui/x-ui setting -listenIP 127.0.0.1 >/dev/null || { [ "$XUI_UPGRADED" = 1 ] && xui_rollback "панель не принимает настройки"; die "не удалось настроить панель"; }
  local tscope=""; /usr/local/x-ui/x-ui setting -h 2>&1 | grep -c -- -tokenScope >/dev/null && tscope="-tokenScope admin"
  # shellcheck disable=SC2086
  ( umask 077; /usr/local/x-ui/x-ui setting -getApiToken -tokenName vpn-setup $tscope 2>/dev/null | awk '/apiToken:/{print $2}' > "$STATE/api.token" ) || true
  [ -s "$STATE/api.token" ] || { [ "$XUI_UPGRADED" = 1 ] && xui_rollback "не выдан API-токен"; die "не удалось получить API-токен панели"; }
  ( umask 077; printf 'Authorization: Bearer %s\n' "$(cat "$STATE/api.token")" > "$STATE/auth.hdr" )
  systemctl enable x-ui >/dev/null 2>&1 || true
  systemctl restart x-ui
  local ok=0 url="http://127.0.0.1:${P_PORT}/${P_PATH}/panel/api/inbounds/list"
  for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null -H @"$STATE/auth.hdr" "$url" 2>/dev/null; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" = 1 ] || { [ "$XUI_UPGRADED" = 1 ] && xui_rollback "панель не отвечает"; journalctl -u x-ui -n 20 --no-pager || true; die "панель не отвечает"; }
  [ "$XUI_UPGRADED" = 1 ] && xui_upgrade_verify
  echo "панель запущена на 127.0.0.1:${P_PORT} (снаружи недоступна)"

  step "5/9 Внешний IP и сайт маскировки Reality"
  PUBLIC_IP=${PUBLIC_IP:-$(detect_public_ip || true)}
  [ -n "$PUBLIC_IP" ] || die "не удалось определить внешний IPv4. Задай: PUBLIC_IP=x.x.x.x bash install.sh"
  [ -n "$ENV_COUNTRY_IN" ] && COUNTRY="$ENV_COUNTRY_IN"
  [ -n "${COUNTRY:-}" ] || COUNTRY=$(detect_country)
  echo "IP сервера: $PUBLIC_IP, страна: ${COUNTRY:-не определена} $(flag_of "${COUNTRY:-}")"
  write_helpers
  local OLD_SNI="${SNI:-}" SNI_CHANGED=0 NEW_DOMAIN="" DOMAIN_NOTE="" ans=""
  # свой домен: новый — проверяем сразу, а подключаем в конце (если не выйдет — установка всё равно завершится)
  if [ -n "$ENV_DOMAIN" ] && [ "$ENV_DOMAIN" != off ]; then
    NEW_DOMAIN=$(domain_normalize "$ENV_DOMAIN") || { DOMAIN_NOTE="некорректное имя домена: $ENV_DOMAIN"; NEW_DOMAIN=""; }
  elif [ "$FRESH" = 1 ] && [ -z "${DOMAIN:-}" ] && [ -z "$ENV_SNI" ] && (: </dev/tty) 2>/dev/null; then
    echo
    echo "Свой домен — самая сильная маскировка: Reality выглядит как твой настоящий сайт на этом сервере."
    echo "Нужна A-запись домена (или поддомена) на $PUBLIC_IP, без Cloudflare-прокси. Нет домена — Enter, включить можно позже."
    ask ans "Свой домен для маскировки (A-запись на IP сервера уже сделана)? Enter — пропустить" ""
    if [ -n "$ans" ]; then NEW_DOMAIN=$(domain_normalize "$ans") || { DOMAIN_NOTE="некорректное имя домена: $ans"; NEW_DOMAIN=""; }; fi
  fi
  if [ -n "$NEW_DOMAIN" ] && [ "$NEW_DOMAIN" = "${DOMAIN:-}" ]; then NEW_DOMAIN=""; fi   # уже включён
  if [ -n "$NEW_DOMAIN" ]; then
    echo "проверяю домен $NEW_DOMAIN (имя, DNS)…"
    if run_self _domain_check "$NEW_DOMAIN" "$PUBLIC_IP"; then
      echo "домен $NEW_DOMAIN указывает на этот сервер ✓ — подключу его в конце установки"
      choose_site_template
    else
      DOMAIN_NOTE="домен $NEW_DOMAIN не прошёл проверку (причина выше)"; NEW_DOMAIN=""
    fi
  fi
  if [ -n "$DOMAIN_NOTE" ]; then
    warn "$DOMAIN_NOTE — продолжаю без своего домена. Включить позже: vpn-setup → пункт 6, или vpn-setup domain ДОМЕН"
  fi
  if [ -n "${DOMAIN:-}" ]; then
    SNI="$DOMAIN"; echo "свой домен: Reality маскируется под собственный сайт $DOMAIN (выключить: vpn-setup domain off)"
  elif [ -n "$ENV_SNI" ]; then SNI=$(choose_sni "$ENV_SNI") || exit 1; [ -n "$OLD_SNI" ] && [ "$OLD_SNI" != "$SNI" ] && SNI_CHANGED=1
  elif [ -n "${SNI:-}" ]; then echo "оставляю прежний сайт (сменить: vpn-setup sni)"
  else
    [ -n "$NEW_DOMAIN" ] && echo "Сначала запасной (чужой) сайт маскировки — он нужен, если свой домен когда-нибудь отключишь."
    SNI=$(choose_sni) || exit 1
  fi
  echo "SNI: $SNI"; echo "$SNI" > "$STATE/sni"
  save_config

  step "6/9 Firewall и fail2ban"
  firewall_apply "$PORT_REALITY" "$PORT_SUDOKU" "$PORT_XHTTP" ${DOMAIN:+80}
  fail2ban_apply
  if [ -n "${DOMAIN:-}" ]; then   # свой домен уже включён: обновить сайт/сертификат; сбой DNS-проверки не ломает работающий сайт
    if run_self _domain_check "$DOMAIN" "$PUBLIC_IP" >/dev/null 2>&1; then domain_setup "$DOMAIN" "$PUBLIC_IP"
    else warn "DNS домена $DOMAIN сейчас проверить не удалось — оставляю сайт как есть"; DOMAIN_SKIP_DNS=1 domain_setup "$DOMAIN" "$PUBLIC_IP"; fi
    ensure_cert_renewal; save_config
  fi

  step "7/9 Inbound'ы и пользователи"
  REALITY_TARGET="${DOMAIN:+127.0.0.1:${DOMAIN_PORT:-}}" run_provision
  if [ -n "${DOMAIN:-}" ]; then SET_SNI="$DOMAIN" REALITY_TARGET="127.0.0.1:$DOMAIN_PORT" run_provision
  elif [ "$SNI_CHANGED" = 1 ]; then SET_SNI="$SNI" run_provision; warn "сайт маскировки сменён: ссылки Reality изменились"; fi

  step "8/9 QR-коды, бэкапы"
  publish_links
  ops_backup
  if [ -f "$STATE/install.sh" ]; then ops_install_backup_cron
  else warn "ежедневный бэкап не включён: нет копии скрипта. Скачай: curl -fsSL $SELF_URL -o $STATE/install.sh и запусти: bash $STATE/install.sh"; fi

  install_cli

  if [ -n "$NEW_DOMAIN" ]; then
    step "Свой домен $NEW_DOMAIN: сайт, сертификат Let's Encrypt, Reality"
    if SITE_TEMPLATE="${SITE_TEMPLATE:-}" VPN_SETUP_QUIET_LINKS=1 run_self domain "$NEW_DOMAIN"; then
      load_config   # DOMAIN, DOMAIN_PORT, SNI — из config.env
      echo "свой домен $DOMAIN подключён: Reality маскируется под твой сайт https://$DOMAIN"
    else
      DOMAIN_NOTE="свой домен $NEW_DOMAIN не подключён (причина выше)"
      warn "$DOMAIN_NOTE. VPN работает, маскировка: ${SNI}. Повторить: vpn-setup → пункт 6, или vpn-setup domain $NEW_DOMAIN"
    fi
  fi

  step "9/9 Проверка"
  local rc=0
  ops_status || rc=$?
  [ -z "$DOMAIN_NOTE" ] || rc=1

  cat > "$STATE/README.txt" <<EOF
vpn-setup ${SCRIPT_VERSION}   Сервер: ${PUBLIC_IP}   SNI Reality: ${SNI}   3X-UI: ${XUI_VERSION}
Профили:  Reality-XHTTP :${PORT_REALITY}  |  Sudoku-VLESSenc :${PORT_SUDOKU}  |  XHTTP-VLESSenc :${PORT_XHTTP}

$(panel_text)

Файлы: ссылки ${STATE}/links.txt   QR ${STATE}/qr/   ключи ${STATE}/keys/   бэкапы ${STATE}/backup/ (ежедневно)
Команды: vpn-setup (меню)   vpn-setup help    (или bash ${STATE}/install.sh help)
$(if [ -n "${DOMAIN:-}" ]; then echo "Свой домен: https://${DOMAIN}  (файлы сайта: ${DOMAIN_WWW_ROOT:-/var/www}/${DOMAIN})"; fi)

================ ССЫЛКИ ПОЛЬЗОВАТЕЛЕЙ (секрет! вставить в Happ / v2rayNG / Throne) ================
$(cat "$STATE/links.txt" 2>/dev/null || echo "нет файла $STATE/links.txt")
EOF
  chmod 600 "$STATE/README.txt"

  install_summary "$rc" "$DOMAIN_NOTE"
}

install_summary(){ # install_summary RC [ЗАМЕЧАНИЕ_ПРО_ДОМЕН] — итог установки в консоль
  local rc="$1" note="${2:-}" yn=""
  echo
  echo "=================================================================="
  if [ "$rc" = 0 ]; then echo -e "${c_ok}ГОТОВО.${c_no}"; else echo -e "${c_warn}ГОТОВО С ЗАМЕЧАНИЯМИ — см. проверку выше.${c_no}"; fi
  [ -z "$note" ] || echo -e "${c_warn}! ${note}. Включить позже: vpn-setup → пункт 6, или vpn-setup domain ДОМЕН${c_no}"
  echo
  # пароль панели — только на экран; если вывод пишется в файл/лог, пароль не печатаем
  if [ -t 1 ]; then panel_text; else panel_text | sed "s|${P_PASS:-__no_password__}|см. $STATE/README.txt|g"; fi
  echo
  echo "ССЫЛКИ ДЛЯ ПРИЛОЖЕНИЙ: $STATE/links.txt   QR-коды: $STATE/qr/   (показать: vpn-setup links)"
  echo "Скачать всё одним файлом (панель, пароли, ссылки): MobaXterm → слева вкладка SFTP → папка $STATE → файл README.txt (и папка qr)."
  echo "Это секреты — не пересылай их в общие чаты."
  echo "Проверь с домашнего ПК без VPN, что сервер доступен:  curl -s -o NUL -w \"%{http_code}\" http://${PUBLIC_IP}:${PORT_XHTTP}/   (ожидается 404)"
  echo "Меню управления сервером:  vpn-setup"
  if [ ! -f /etc/ssh/sshd_config.d/00-hardening.conf ]; then
    warn "Вход по паролю ещё включён. Зайди по ключу в НОВОЙ сессии, затем выполни:  vpn-setup harden-ssh"
  fi
  if [ -t 1 ] && (: </dev/tty) 2>/dev/null; then
    read -r -p "Показать ссылки пользователей сейчас? [y/N]: " yn </dev/tty || yn=""
    case "$yn" in y|Y|д|Д|yes|да) ops_links ;; esac
  fi
  return 0
}

# ===================== меню =====================
menu_pause(){ local _x; read -r -p "Enter — назад в меню… " _x </dev/tty || true; }
menu_run(){ # menu_run КОМАНДА… — подкоманда отдельным процессом; Ctrl+C прерывает её, а не меню
  local rc=0
  echo
  trap ':' INT
  run_self "$@" || rc=$?
  trap - INT
  [ "$rc" = 0 ] || echo -e "${c_warn}(команда завершилась с ошибкой, код $rc)${c_no}"
  return 0
}
menu_header(){
  local out nf nw st="" x="" tgt
  echo
  echo "=================================================================="
  if ! is_installed; then
    echo " vpn-setup ${SCRIPT_VERSION} — VPN на этом сервере ещё НЕ настроен"
    echo "=================================================================="
    return 0
  fi
  load_config
  x=$(/usr/local/x-ui/x-ui -v 2>/dev/null | tr -dc '0-9.\n' | sed -n 1p) || true
  if [ -n "${DOMAIN:-}" ]; then tgt="свой домен ${DOMAIN}"; else tgt="сайт ${SNI:-?}"; fi
  echo " vpn-setup ${SCRIPT_VERSION} · 3X-UI ${x:-?} · $(flag_of "${COUNTRY:-}") ${PUBLIC_IP:-?}"
  echo " Пользователей: $(wc -w <<<"${USERS:-}") · маскировка Reality: ${tgt}"
  printf ' Состояние: проверяю…\r'
  out=$(run_self status 2>&1 | sed 's/\x1b\[[0-9;]*m//g') || true
  nf=$(grep -c '^  ✗' <<<"$out") || nf=0
  nw=$(grep -c '^  !' <<<"$out") || nw=0
  if [ "$nf" = 0 ] && [ "$nw" = 0 ]; then st="${c_ok}✓ всё в порядке${c_no}"
  elif [ "$nf" = 0 ]; then st="${c_warn}! замечаний: $nw${c_no} (пункт 2)"
  else st="${c_err}✗ проблем: $nf${c_no}, замечаний: $nw (пункт 2)"; fi
  echo -e " Состояние: ${st}            "
  echo "=================================================================="
}
menu_main(){ # интерактивное меню (как у x-ui); выход — 0
  local c="" v=""
  while true; do
    menu_header
    if ! is_installed; then
      cat <<'MENU'
  1) Установить VPN
  2) Проверить IP до установки (не режет ли провайдер)
  3) Справка по командам
  0) Выход
MENU
      read -r -p "Выбери пункт: " c </dev/tty || return 0
      case "$c" in
        1) menu_run install; menu_pause ;;
        2) menu_run precheck; menu_pause ;;
        3) ops_help; menu_pause ;;
        0|q|exit|"") return 0 ;;
        *) echo "нет такого пункта" ;;
      esac
      continue
    fi
    cat <<'MENU'
  1) Обновить скрипт (с GitHub)          7) Сайт-заглушка своего домена
  2) Состояние сервера                   8) Чужой сайт маскировки Reality
  3) Ссылки и QR-коды                    9) Отключить вход по паролю (SSH)
  4) Вход в панель 3X-UI (SSH-туннель)  10) Бэкап сейчас
  5) Добавить пользователей             11) Повторить установку / проверку
  6) Свой домен                         12) Удалить VPN
  0) Выход
MENU
    read -r -p "Выбери пункт: " c </dev/tty || return 0
    case "$c" in
      1) menu_run update && { [ -f "$STATE/install.sh" ] && exec bash "$STATE/install.sh"; }; menu_pause ;;
      2) menu_run status; menu_pause ;;
      3) v=""; read -r -p "Имя пользователя (Enter — все): " v </dev/tty || v=""
         menu_run links "$v"; menu_pause ;;
      4) menu_run panel; menu_pause ;;
      5) v=""; read -r -p "Новые имена латиницей через пробел (Enter — отмена): " v </dev/tty || v=""
         if [ -n "${v// /}" ]; then
           if [[ "$v" =~ ^[A-Za-z0-9_\ -]+$ ]]; then USERS="$v" menu_run install
           else echo "имена — только латиница, цифры, _ и -"; fi
         fi
         menu_pause ;;
      6) menu_run domain
         v=""; read -r -p "Домен или поддомен (off — выключить, Enter — назад): " v </dev/tty || v=""
         if [ "$v" = off ]; then menu_run domain off
         elif [ -n "$v" ]; then
           SITE_TEMPLATE=""; choose_site_template
           SITE_TEMPLATE="${SITE_TEMPLATE:-}" menu_run domain "$v"; SITE_TEMPLATE=""
         fi
         menu_pause ;;
      7) load_config
         if [ -z "${DOMAIN:-}" ]; then echo "Сначала включи свой домен (пункт 6) — сайт-заглушка бывает только на своём домене."
         else menu_run site; fi
         menu_pause ;;
      8) menu_run sni; menu_pause ;;
      9) menu_run harden-ssh; menu_pause ;;
      10) menu_run backup; menu_pause ;;
      11) menu_run install; menu_pause ;;
      12) menu_run uninstall; menu_pause ;;
      0|q|exit|"") return 0 ;;
      *) echo "нет такого пункта" ;;
    esac
  done
}

# ===================== запуск =====================
# Запуск через "bash <(curl ...)": сохраняем себя в $STATE и продолжаем из файла
# (нужно для ежедневного бэкапа по cron и последующих команд).
if [ "$(id -u)" = 0 ] && [ ! -f "$0" ] && [ -z "${VPN_SETUP_REEXEC:-}" ] && [ "${SELF_URL#@@}" = "$SELF_URL" ]; then
  install -d -m 700 "$STATE"
  # сначала ссылка на тег версии; если тега ещё нет — та же версия из main
  if { curl -fsSL --retry 2 --connect-timeout 15 -o "$STATE/install.sh.new" "$SELF_URL" 2>/dev/null \
       || curl -fsSL --retry 2 --connect-timeout 15 -o "$STATE/install.sh.new" "${SELF_URL%/*/install.sh}/main/install.sh"; } \
     && bash -n "$STATE/install.sh.new" \
     && grep -c "^SCRIPT_VERSION=\"${SCRIPT_VERSION}\"$" "$STATE/install.sh.new" >/dev/null; then
    mv "$STATE/install.sh.new" "$STATE/install.sh"; chmod 700 "$STATE/install.sh"
    VPN_SETUP_REEXEC=1 exec bash "$STATE/install.sh" "$@"
  fi
  rm -f "$STATE/install.sh.new"
  warn "не удалось сохранить копию скрипта — ежедневный бэкап по cron работать не будет"
fi
if [ -f "$0" ] && [ "$(id -u)" = 0 ] && [ "$(readlink -f "$0")" != "$(readlink -f "$STATE/install.sh" 2>/dev/null || true)" ]; then
  install -d -m 700 "$STATE"; install -m 700 "$0" "$STATE/install.sh"
fi

# без аргументов в терминале — меню; с переменными USERS/SNI/DOMAIN/… или без терминала — сразу установка
if [ $# = 0 ] && [ "${VPN_SETUP_MENU:-1}" != 0 ] && [ -t 0 ] && [ -t 1 ] && (: </dev/tty) 2>/dev/null \
   && [ -z "${USERS:-}${SNI:-}${DOMAIN:-}${COUNTRY:-}${SSH_PUBKEY:-}${SITE_TEMPLATE:-}" ] && [ -n "$(self_path)" ]; then
  menu_main; exit 0
fi

case "${1:-install}" in
  install)      cmd_install ;;
  _domain_check) domain_name_check "${2:?}"; domain_dns_check "${2:?}" "${3:?}" ;;
  site)         [ "$(id -u)" = 0 ] || die "нужен root"
                if declare -F cmd_site >/dev/null; then cmd_site "${2:-}"; else die "команда site появится вместе с модулем шаблонов сайтов"; fi ;;
  menu)         menu_main ;;
  harden-ssh)   [ "$(id -u)" = 0 ] || die "нужен root"; harden_ssh ;;
  sni)          [ "$(id -u)" = 0 ] || die "нужен root"; cmd_sni "${2:-}" ;;
  domain)       [ "$(id -u)" = 0 ] || die "нужен root"; cmd_domain "${2:-}" ;;
  precheck)     cmd_precheck "${2:-}" ;;
  panel|tunnel) cmd_panel ;;
  update)       cmd_update ;;
  status)       require_installed; load_config; ops_status || exit 1 ;;
  links)        require_installed; load_config; ops_links "${2:-}" ;;
  backup)       require_installed; load_config; ops_backup "${2:-}" ;;
  uninstall)    require_installed; load_config; ops_uninstall ;;
  version|-v)   echo "vpn-setup ${SCRIPT_VERSION}, 3X-UI ${XUI_VERSION}" ;;
  help|-h|--help) ops_help ;;
  *)            ops_help; die "неизвестная команда: $1" ;;
esac
