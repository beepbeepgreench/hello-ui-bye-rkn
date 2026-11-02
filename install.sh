#!/usr/bin/env bash
# vpn-setup v1.0.1 — 3X-UI + Xray: Reality-XHTTP, VLESS-enc+Sudoku, XHTTP-enc
# Ubuntu 22.04 / 24.04 / 26.04, amd64/arm64, запуск от root, на ЧИСТОМ сервере.
#
#   Установка:   bash <(curl -fsSL https://raw.githubusercontent.com/beepbeepgreench/hello-ui-bye-rkn/v1.0.1/install.sh)
#   Потом:       bash /root/vpn-setup/install.sh help
#
# Переменные (необязательно, иначе спросит): USERS, SSH_PUBKEY, SNI, PORT_REALITY, PORT_SUDOKU, PORT_XHTTP
set -Eeuo pipefail

SCRIPT_VERSION="v1.0.1"
SELF_URL="https://raw.githubusercontent.com/beepbeepgreench/hello-ui-bye-rkn/v1.0.1/install.sh"
XUI_VERSION="v3.8.5"   # закреплено: проверено с Xray 26.9.9 (Reality-XHTTP, Sudoku, VLESS-enc)
declare -A XUI_SHA256=(
  [amd64]="6a85c110a04a727613c933c54ae602b8d37dab8876c6e20a6d46623010dd9d3c"
  [arm64]="2dd601a32426fb19b0eafdffaead374a9cdb66be4dfb39407f9f50fa4e7234e7"
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
  Сначала добавь ключ: SSH_PUBKEY='ssh-ed25519 AAAA...' bash install.sh"
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
# создано vpn-setup (bash install.sh harden-ssh). Откат: удалить файл и systemctl reload ssh
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
  out=$(pgrep -x -- "$name" 2>/dev/null | head -n1) || out=""
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
  out=$(sshd -T 2>/dev/null | awk '/^passwordauthentication /{print $2; exit}') || out=""
  case "$out" in
    no)  _ops_mark ok "SSH: вход по паролю выключен";;
    yes) _ops_mark warn "SSH: вход по паролю ВКЛЮЧЁН (после проверки входа по ключу: bash install.sh harden-ssh)";;
    *)   _ops_mark warn "SSH: не удалось определить (sshd -T)";;
  esac

  if [ -f /var/run/reboot-required ]; then
    l=$(sort -u /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ') || l=""
    _ops_mark warn "нужна перезагрузка${l:+ (пакеты: ${l% })}"
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
    _ops_mark warn "бэкапов нет: bash install.sh backup"
  else
    p=${out%%.*}; l=$(( ($(date +%s) - p) / 3600 ))
    if [ "$l" -gt 48 ]; then _ops_mark warn "последний бэкап $((l / 24)) дн. назад: ${out#* }"
    else _ops_mark ok "последний бэкап $l ч назад: $(basename "${out#* }")"; fi
  fi
  if [ -f "$CRON_FILE" ]; then _ops_mark ok "ежедневный бэкап по cron: включён"
  else _ops_mark warn "ежедневный бэкап по cron не настроен"; fi

  out=$(timeout 10 "$XUI_DIR/x-ui" -v 2>/dev/null | head -n1) || out=""
  l=$(timeout 10 "$XRAY_BIN" version 2>/dev/null | awk 'NR==1{print $2; exit}') || l=""
  if [ -n "$out" ] && [ -n "$l" ]; then
    if [ -n "${XUI_VERSION:-}" ] && [ "$out" != "${XUI_VERSION#v}" ]; then _ops_mark warn "версии: 3X-UI $out (ожидалась ${XUI_VERSION#v}), Xray $l"
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
  ssh_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}') || ssh_port=""

  echo "Будет удалено: 3X-UI ($XUI_DIR, $XUI_ETC, $XUI_LOG, $XUI_UNIT, $XUI_CLI), cron бэкапа,"
  echo "правила UFW для портов ${PORT_REALITY:-443} ${PORT_SUDOKU:-8443} ${PORT_XHTTP:-8080}/tcp."
  echo "Перед удалением: финальный бэкап → $final; $STATE будет переименован в $dest."
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

Использование:  bash install.sh [команда]

  precheck [ПОРТ]   ДО установки: проверить, доходят ли данные с домашнего ПК до этого IP
                    (на ПК в это время: bash check-server.sh IP ПОРТ)
  (без команды)     установка или обновление; повторный запуск безопасен,
                    новые имена из USERS добавляются, старые ссылки не меняются
  harden-ssh        отключить вход по паролю (только после проверки входа по ключу!)
  sni [ДОМЕН]       подобрать/проверить сайт маскировки Reality (без аргумента — подбор)
  status            проверка состояния: службы, порты, firewall, fail2ban, SSH, диск, RAM,
                    бэкапы, версии; код выхода 1, если есть ✗
  links [ИМЯ]       показать ссылки (всех или одного пользователя) и пересоздать QR в /root/vpn-setup/qr/
  backup            бэкап базы панели и ключей в /root/vpn-setup/backup/ (хранятся 14 последних)
  uninstall         удалить 3X-UI (с финальным бэкапом в /root; SSH и firewall для SSH не трогает).
                    Подтверждение: ввести 'удалить' или UNINSTALL_CONFIRM=yes; DRY_RUN=1 — только показать
  version           версия скрипта и 3X-UI
  help              эта справка

Переменные установки: USERS, SSH_PUBKEY, SNI, PORT_REALITY, PORT_SUDOKU, PORT_XHTTP
EOF
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
    printf 'USERS=%q\nSNI=%q\nPORT_REALITY=%q\nPORT_SUDOKU=%q\nPORT_XHTTP=%q\nPUBLIC_IP=%q\nINSTALLED_VERSION=%q\n' \
      "${USERS:-}" "${SNI:-}" "$PORT_REALITY" "$PORT_SUDOKU" "$PORT_XHTTP" "${PUBLIC_IP:-}" "$SCRIPT_VERSION" > "$STATE/config.env" )
}
require_installed(){
  [ -f "$STATE/panel.env" ] && [ -x /usr/local/x-ui/x-ui ] || die "установка не найдена. Сначала: bash install.sh"
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


def set_sni(dom):
    """SET_SNI mode: point vpn-reality at another camouflage site; idempotent, with rollback."""
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}", dom):
        die(f"SET_SNI: некорректное доменное имя {dom!r}")
    ib = next((i for i in (api("GET", "/panel/api/inbounds/list") or []) if i.get("tag") == "vpn-reality"), None)
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
    if rs.get("target") == f"{dom}:443" and was == [dom]:
        print(f"SNI: уже {dom} (inbound id {iid}), изменений нет")
    else:
        rs["target"], rs["serverNames"] = f"{dom}:443", [dom]
        body = dict(old, streamSettings=json.dumps(stream) if isinstance(raw, str) else stream)
        api("POST", f"/panel/api/inbounds/update/{iid}", body)
        print(f"SNI: {', '.join(was) or '—'} → {dom} (inbound id {iid})")

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

INBOUNDS = [
    {"tag": "vpn-reality", "remark": "Reality-XHTTP", "port": P_REALITY,
     "settings": {"clients": [], "decryption": "none", "fallbacks": []},
     "stream": {"network": "xhttp", "security": "reality",
                "xhttpSettings": dict(XHTTP_BASE, path=p_reality),
                "realitySettings": {"show": False, "xver": 0, "target": f"{SNI}:443", "serverNames": [SNI],
                                    "privateKey": reality["private"], "shortIds": [sid],
                                    "minClientVer": "", "maxClientVer": "", "maxTimediff": 0,
                                    "settings": {"publicKey": reality["public"], "fingerprint": "firefox",
                                                 "serverName": "", "spiderX": "/"}}}},
    {"tag": "vpn-sudoku", "remark": "Sudoku-VLESSenc", "port": P_SUDOKU,
     "settings": {"clients": [], "decryption": venc["decryption"], "encryption": venc["encryption"]},
     "stream": {"network": "tcp", "security": "none",
                "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
                "finalmask": {"tcp": [{"type": "sudoku", "settings": {
                    "password": sudoku_pw, "ascii": "", "customTable": "", "customTables": [],
                    "paddingMin": 0, "paddingMax": 0}}]}}},
    {"tag": "vpn-xhttp", "remark": "XHTTP-VLESSenc", "port": P_XHTTP,
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

existing = {ib["tag"]: ib for ib in (api("GET", "/panel/api/inbounds/list") or [])}
ids, new_ids = [], []
for d in INBOUNDS:
    if d["tag"] in existing:
        ib = existing[d["tag"]]
        ids.append(ib["id"])
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
  --no-http, --timeout S, --candidates a,b,c (заменить встроенный список), --non-interactive.
"""
import argparse, ipaddress, json, os, queue, re, shutil, socket, ssl, subprocess, sys, tempfile, threading, time
from urllib.parse import urlsplit

OK, WARN, FAIL = 0, 1, 2
VNAME = {OK: "OK", WARN: "WARN", FAIL: "FAIL"}
LATENCY_WARN_MS = 150

# Скучные, посещаемые, неполитические сайты; страна — для подсказки. Всё проверяется на лету,
# CDN-фронтированные отсеются проверкой, так что список намеренно с запасом.
CANDIDATES = [
    ("www.lidl.de", "DE"), ("www.otto.de", "DE"), ("www.dhl.de", "DE"), ("www.rewe.de", "DE"),
    ("www.bahn.de", "DE"), ("www.kaufland.de", "DE"), ("www.dm.de", "DE"), ("www.hornbach.de", "DE"),
    ("www.ah.nl", "NL"), ("www.ns.nl", "NL"), ("www.postnl.nl", "NL"), ("www.jumbo.com", "NL"),
    ("www.s-kanava.fi", "FI"), ("www.k-ruoka.fi", "FI"), ("www.posti.fi", "FI"), ("www.vr.fi", "FI"),
    ("www.ica.se", "SE"), ("www.postnord.se", "SE"), ("www.sj.se", "SE"),
    ("www.inpost.pl", "PL"), ("www.intercity.pl", "PL"), ("www.pkobp.pl", "PL"), ("www.biedronka.pl", "PL"),
    ("www.carrefour.fr", "FR"), ("www.laposte.fr", "FR"), ("www.leroymerlin.fr", "FR"),
    ("www.billa.at", "AT"), ("www.oebb.at", "AT"), ("www.post.at", "AT"),
    ("www.alza.cz", "CZ"), ("www.cd.cz", "CZ"), ("www.seznam.cz", "CZ"),
    ("www.rimi.ee", "EE"), ("www.omniva.ee", "EE"),
    ("www.rimi.lv", "LV"), ("www.airbaltic.com", "LV"),
    ("www.maxima.lt", "LT"), ("www.post.lt", "LT"),
    ("www.esselunga.it", "IT"), ("www.poste.it", "IT"), ("www.trenitalia.com", "IT"),
    ("www.mercadona.es", "ES"), ("www.renfe.com", "ES"), ("www.correos.es", "ES"),
]

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

OPT = argparse.Namespace(resolve={}, port=443, cafile=None, no_http=False, timeout=4.0)


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
    if len(lab) >= 3 and lab[-2] in _2LD and len(lab[-1]) == 2:
        return ".".join(lab[-3:])
    return ".".join(lab[-2:])


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


def check(domain):
    d = domain.strip().lower().rstrip(".")
    r = {"domain": d, "ip": None, "verdict": OK, "reasons": [], "latency_ms": None, "tls13": None,
         "alpn": None, "cert_ok": None, "x25519": None, "http_status": None, "cdn": None}

    def bad(level, msg):
        r["reasons"].append(msg)
        r["verdict"] = max(r["verdict"], level)

    def done():
        r["verdict_name"] = VNAME[r["verdict"]]
        return r

    if d.startswith(("http://", "https://")):
        d = urlsplit(d).hostname or ""
        r["domain"] = d
    if not HOST_RE.match(d):
        bad(FAIL, "некорректное доменное имя (нужно вида www.example.de, без IP и пути)")
        return done()
    try:
        ips = resolve4(d)
    except (OSError, TimeoutError):
        ips = []
    if not ips:
        bad(FAIL, "нет DNS A-записи (домен не резолвится в IPv4)")
        return done()
    ip = r["ip"] = ips[0]
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
    return done()


def summary(r):
    if r["reasons"]:
        return r["reasons"][0] + (f" (+{len(r['reasons']) - 1})" if len(r["reasons"]) > 1 else "")
    parts = ["TLS1.3", "h2", "X25519"]
    if r.get("http_status"):
        parts.append(f"HTTP {r['http_status']}")
    return " ".join(parts)


def print_check(r, out=sys.stdout):
    lat = f", {r['latency_ms']} мс" if r["latency_ms"] is not None else ""
    print(f"{r['domain']}: {r['verdict_name']}  (IP {r['ip'] or '—'}{lat})", file=out)
    for m in r["reasons"] or ["все проверки пройдены: TLS 1.3, h2, X25519, сертификат, HTTP"]:
        print(f"  - {m}", file=out)


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
            continue  # wildcard в SNI не подставить
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


def scan(neighbors=None, candidates=None, quiet=False):
    t_start = time.monotonic()
    say = (lambda *_: None) if quiet else log
    jobs = []  # (domain, source)
    if neighbors:
        try:
            hosts = neighbor_hosts(neighbors)
        except ValueError as e:
            say(f"соседи: пропускаю — {e}")
            hosts = []
        if hosts:
            say(f"сканирую соседей {neighbors}/24 на порту {OPT.port} ({len(hosts)} адресов, до 30 с)…")
            pr = parallel(probe_neighbor, hosts, 64, time.monotonic() + 30)
            found = 0
            for v in pr.values():
                if isinstance(v, tuple) and v[1]:
                    found += 1
                    for n in v[1][:4]:
                        if all(n != j[0] for j in jobs):
                            jobs.append((n, f"сосед {v[0]}"))
            say(f"соседи: TLS1.3+h2 отвечают {found}, имён для проверки {len(jobs)}")
    for d, cc in (candidates if candidates is not None else CANDIDATES):
        if all(d != j[0] for j in jobs):
            jobs.append((d, cc))
    say(f"проверяю {len(jobs)} сайтов (до 60 с)…")
    res = parallel(lambda j: check(j[0]), jobs, 16, time.monotonic() + 60)
    rows = []
    for i, (d, src) in enumerate(jobs):
        r = res.get(i)
        if not isinstance(r, dict):
            r = {"domain": d, "ip": None, "verdict": FAIL, "verdict_name": "FAIL", "latency_ms": None,
                 "reasons": ["проверка не уложилась во время" if r is None else f"ошибка проверки: {r}"]}
        r["source"] = src
        r["neighbor"] = src.startswith("сосед")
        rows.append(r)
    rows.sort(key=lambda r: (0 if r["neighbor"] and r["verdict"] == OK else 1, r["verdict"],
                             r["latency_ms"] if r["latency_ms"] is not None else 10 ** 6, r["domain"]))
    say(f"готово за {time.monotonic() - t_start:.0f} с")
    return rows


def print_table(rows, limit, out):
    shown = [r for r in rows if r["verdict"] != FAIL][:limit]
    failed = [r for r in rows if r["verdict"] == FAIL]
    if shown:
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
        best = next((r for r in rows if r["verdict"] == OK), None)
        print_table(rows, args.limit, sys.stderr)
        if not best:
            log("нет ни одного сайта с итогом OK — укажите домен вручную (SNI=...)")
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
        rows = sorted(rows + [cur], key=lambda r: (0 if r["neighbor"] and r["verdict"] == OK else 1, r["verdict"],
                                                   r["latency_ms"] if r["latency_ms"] is not None else 10 ** 6))
    shown = print_table(([cur] if cur and cur["verdict"] == OK else []) + rows, args.limit, tty)
    if cur and cur["verdict"] == FAIL:
        say(f"текущий {cur['domain']} больше не подходит: {'; '.join(cur['reasons'])}")
    dflt = shown[0] if shown else None
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
  XRAY_BIN="$XRAY_BIN" PUBLIC_IP="$PUBLIC_IP" USERS="$USERS" SNI="$SNI" \
  PORT_REALITY="$PORT_REALITY" PORT_SUDOKU="$PORT_SUDOKU" PORT_XHTTP="$PORT_XHTTP" \
    python3 -I "$STATE/provision.py"
}
publish_links(){
  cp "$STATE/keys/links.txt" "$STATE/links.txt"; chmod 600 "$STATE/links.txt"
  ops_links >/dev/null
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
  python3 -I "$STATE/sni.py" check "$1" >&2 || rc=$?
  case $rc in
    0) return 0 ;;
    1) warn "$1 прошёл с замечаниями (выше) — использую" ;;
    *) die "сайт $1 не подходит для маскировки (причины выше). Другой: SNI=домен, или без проверки: SNI_SKIP_CHECK=1" ;;
  esac
}
choose_sni(){ # choose_sni [ЯВНЫЙ_ДОМЕН] — печатает выбранный домен
  local d="${1:-}"
  if [ -n "$d" ]; then check_sni "$d"; echo "$d"; return 0; fi
  d=$(python3 -I "$STATE/sni.py" pick --neighbors "$PUBLIC_IP" ${SNI:+--default "$SNI"} | tail -n 1) || true
  [ -n "$d" ] || die "не удалось подобрать сайт маскировки. Задай вручную: SNI=www.example.de bash install.sh"
  echo "$d"
}

# ===================== подкоманды =====================
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
  write_helpers
  PUBLIC_IP=${PUBLIC_IP:-$(detect_public_ip || true)}
  step "Смена сайта маскировки Reality (сейчас: ${SNI:-не задан})"
  SNI=$(choose_sni "$new") || exit 1
  echo "Выбрано: $SNI"
  SET_SNI="$SNI" run_provision
  save_config; publish_links
  warn "Ссылки и QR профиля Reality изменились: раздай пользователям новые (bash $STATE/install.sh links)."
}

cmd_install(){
  step "0/9 Проверки"
  [ "$(id -u)" = 0 ] || die "запусти от root"
  # shellcheck disable=SC1091
  . /etc/os-release
  [ "${ID:-}" = ubuntu ] || die "поддерживается только Ubuntu 22.04/24.04/26.04 (обнаружено: ${PRETTY_NAME:-?})"
  case "${VERSION_ID:-}" in 22.04|24.04|26.04) ;; *) warn "Ubuntu ${VERSION_ID:-?} не проверялась — продолжаю на свой риск";; esac
  local ENV_SNI="${SNI:-}" ENV_USERS="${USERS:-}"
  load_config
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
  if [ ! -x /usr/local/x-ui/x-ui ] || ! /usr/local/x-ui/x-ui -v 2>/dev/null | grep -c "${XUI_VERSION#v}" >/dev/null; then
    local TMP; TMP=$(mktemp -d)
    curl -fsSL --retry 3 --connect-timeout 15 -o "$TMP/x-ui.tgz" \
      "https://github.com/MHSanaei/3x-ui/releases/download/${XUI_VERSION}/x-ui-linux-${ARCH}.tar.gz" \
      || die "не удалось скачать 3X-UI с GitHub (доступ к github.com с сервера?)"
    echo "${XUI_SHA256[$ARCH]}  $TMP/x-ui.tgz" | sha256sum -c --quiet - || die "контрольная сумма архива не совпала — установка остановлена"
    echo "контрольная сумма совпала"
    systemctl stop x-ui 2>/dev/null || true
    tar xzf "$TMP/x-ui.tgz" -C "$TMP"
    rm -rf /usr/local/x-ui && mv "$TMP/x-ui" /usr/local/x-ui && rm -rf "$TMP"
    chmod +x /usr/local/x-ui/x-ui "$XRAY_BIN" /usr/local/x-ui/x-ui.sh
    install -m 755 /usr/local/x-ui/x-ui.sh /usr/bin/x-ui
    install -m 644 /usr/local/x-ui/x-ui.service.debian /etc/systemd/system/x-ui.service
    install -d /var/log/x-ui
    systemctl daemon-reload
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
  /usr/local/x-ui/x-ui setting -listenIP 127.0.0.1 >/dev/null
  ( umask 077; /usr/local/x-ui/x-ui setting -getApiToken -tokenName vpn-setup 2>/dev/null | awk '/apiToken:/{print $2}' > "$STATE/api.token" ) || true
  [ -s "$STATE/api.token" ] || die "не удалось получить API-токен панели"
  ( umask 077; printf 'Authorization: Bearer %s\n' "$(cat "$STATE/api.token")" > "$STATE/auth.hdr" )
  systemctl enable x-ui >/dev/null 2>&1 || true
  systemctl restart x-ui
  local ok=0 url="http://127.0.0.1:${P_PORT}/${P_PATH}/panel/api/inbounds/list"
  for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null -H @"$STATE/auth.hdr" "$url" 2>/dev/null; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" = 1 ] || { journalctl -u x-ui -n 20 --no-pager || true; die "панель не отвечает"; }
  echo "панель запущена на 127.0.0.1:${P_PORT} (снаружи недоступна)"

  step "5/9 Внешний IP и сайт маскировки Reality"
  PUBLIC_IP=${PUBLIC_IP:-$(detect_public_ip || true)}
  [ -n "$PUBLIC_IP" ] || die "не удалось определить внешний IPv4. Задай: PUBLIC_IP=x.x.x.x bash install.sh"
  echo "IP сервера: $PUBLIC_IP"
  write_helpers
  local OLD_SNI="${SNI:-}" SNI_CHANGED=0
  if [ -n "$ENV_SNI" ]; then SNI=$(choose_sni "$ENV_SNI") || exit 1; [ -n "$OLD_SNI" ] && [ "$OLD_SNI" != "$SNI" ] && SNI_CHANGED=1
  elif [ -n "${SNI:-}" ]; then echo "оставляю прежний сайт (сменить: bash $STATE/install.sh sni)"
  else SNI=$(choose_sni) || exit 1; fi
  echo "SNI: $SNI"; echo "$SNI" > "$STATE/sni"
  save_config

  step "6/9 Firewall и fail2ban"
  firewall_apply "$PORT_REALITY" "$PORT_SUDOKU" "$PORT_XHTTP"
  fail2ban_apply

  step "7/9 Inbound'ы и пользователи"
  run_provision
  if [ "$SNI_CHANGED" = 1 ]; then SET_SNI="$SNI" run_provision; warn "сайт маскировки сменён: ссылки Reality изменились"; fi

  step "8/9 QR-коды, бэкапы"
  publish_links
  ops_backup
  if [ -f "$STATE/install.sh" ]; then ops_install_backup_cron
  else warn "ежедневный бэкап не включён: нет копии скрипта. Скачай: curl -fsSL $SELF_URL -o $STATE/install.sh и запусти: bash $STATE/install.sh"; fi

  step "9/9 Проверка"
  local rc=0
  ops_status || rc=$?

  cat > "$STATE/README.txt" <<EOF
vpn-setup ${SCRIPT_VERSION}   Сервер: ${PUBLIC_IP}   SNI Reality: ${SNI}   3X-UI: ${XUI_VERSION}
Профили:  Reality-XHTTP :${PORT_REALITY}  |  Sudoku-VLESSenc :${PORT_SUDOKU}  |  XHTTP-VLESSenc :${PORT_XHTTP}

Панель (только через SSH-туннель):
  MobaXterm → Tunneling → Local port forwarding: ${P_PORT} → 127.0.0.1:${P_PORT} через ${PUBLIC_IP}
  Браузер: http://127.0.0.1:${P_PORT}/${P_PATH}/
  Логин: ${P_USER}   Пароль: ${P_PASS}

Файлы: ссылки ${STATE}/links.txt   QR ${STATE}/qr/   ключи ${STATE}/keys/   бэкапы ${STATE}/backup/ (ежедневно)
Команды: bash ${STATE}/install.sh help
EOF
  chmod 600 "$STATE/README.txt"

  echo
  if [ "$rc" = 0 ]; then echo -e "${c_ok}ГОТОВО.${c_no}"; else echo -e "${c_warn}ГОТОВО С ЗАМЕЧАНИЯМИ — см. проверку выше.${c_no}"; fi
  echo "Логин панели, туннель, файлы: cat $STATE/README.txt"
  echo "Скачай через SFTP папку $STATE/qr и файл $STATE/links.txt — это секреты."
  echo "Проверь с домашнего ПК без VPN, что сервер доступен:  curl -s -o NUL -w \"%{http_code}\" http://${PUBLIC_IP}:${PORT_XHTTP}/   (ожидается 404)"
  if [ ! -f /etc/ssh/sshd_config.d/00-hardening.conf ]; then
    warn "Вход по паролю ещё включён. Зайди по ключу в НОВОЙ сессии, затем: bash $STATE/install.sh harden-ssh"
  fi
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

case "${1:-install}" in
  install)      cmd_install ;;
  harden-ssh)   [ "$(id -u)" = 0 ] || die "нужен root"; harden_ssh ;;
  sni)          [ "$(id -u)" = 0 ] || die "нужен root"; cmd_sni "${2:-}" ;;
  precheck)     cmd_precheck "${2:-}" ;;
  status)       require_installed; load_config; ops_status || exit 1 ;;
  links)        require_installed; load_config; ops_links "${2:-}" ;;
  backup)       require_installed; load_config; ops_backup "${2:-}" ;;
  uninstall)    require_installed; load_config; ops_uninstall ;;
  version|-v)   echo "vpn-setup ${SCRIPT_VERSION}, 3X-UI ${XUI_VERSION}" ;;
  help|-h|--help) ops_help ;;
  *)            ops_help; die "неизвестная команда: $1" ;;
esac
