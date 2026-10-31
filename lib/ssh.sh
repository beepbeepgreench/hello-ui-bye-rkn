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
