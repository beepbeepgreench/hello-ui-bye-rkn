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
