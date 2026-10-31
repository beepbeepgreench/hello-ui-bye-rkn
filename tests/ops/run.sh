#!/usr/bin/env bash
# Тесты lib/ops.sh. Живую установку (/usr/local/x-ui, /etc/x-ui, /root/vpn-setup) только ЧИТАЕМ.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
H="$HERE/harness.sh"
ROOT=$(cd "$HERE/../.." && pwd)
PASS=0; FAILN=0
ok(){ echo "PASS: $*"; PASS=$((PASS + 1)); }
bad(){ echo "FAIL: $*"; FAILN=$((FAILN + 1)); }
check(){ local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
T=$(mktemp -d /tmp/ops-test.XXXXXX); trap 'rm -rf "$T"' EXIT
LIVE_STATE=/root/vpn-setup
snap_live(){ { find /usr/local/x-ui "$LIVE_STATE" /etc/x-ui -printf '%p %s %m\n' 2>/dev/null | grep -v -e '/x-ui.db' -e '/access.log' -e '/error.log' -e '\.gob ' -e '^/etc/x-ui ' | sort; ls /etc/cron.d; }; }
snap_live > "$T/live.before"

echo "== static"
check "bash -n lib/ops.sh" bash -n "$ROOT/lib/ops.sh"
check "shellcheck -S warning lib/ops.sh" shellcheck -S warning -s bash "$ROOT/lib/ops.sh"
check "top level: при source нет вывода и не создаётся ни одной переменной" \
  bash -c 'set -Eeuo pipefail; trap "exit 9" ERR; b=$(compgen -v | grep -vx b | sort); . "$1" > "$2"; a=$(compgen -v | grep -vx -e a -e b | sort); [ ! -s "$2" ] && [ "$b" = "$a" ]' _ "$ROOT/lib/ops.sh" "$T/src.out"

# ---------- stubs ----------
STUBS="$T/stubs"; mkdir -p "$STUBS"; export CALLS_LOG="$T/calls.log"; : > "$CALLS_LOG"
for c in systemctl ufw fail2ban-client crontab; do
  cat > "$STUBS/$c" <<EOF
#!/bin/sh
echo "$c \$*" >> "$CALLS_LOG"
case "$c \$1" in
  "systemctl is-active") echo active;;
  "ufw status") printf 'Status: active\n\nTo   Action  From\n--   ------  ----\n22/tcp  ALLOW  Anywhere  # ssh\n443/tcp  ALLOW  Anywhere\n8443/tcp  ALLOW  Anywhere\n8080/tcp ALLOW Anywhere\n';;
  "fail2ban-client status") printf 'Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n|  \`- Total failed:\t3\n\`- Actions\n   |- Currently banned:\t2\n   \`- Total banned:\t7\n';;
esac
exit 0
EOF
  chmod +x "$STUBS/$c"
done
cat > "$STUBS/sshd" <<EOF
#!/bin/sh
echo "sshd \$*" >> "$CALLS_LOG"
printf 'port 22\npasswordauthentication no\n'
EOF
chmod +x "$STUBS/sshd"

echo "== status (живая установка, реальные systemctl/ufw — в песочнице их нет)"
S1="$T/s1"; mkdir -p "$S1"; cp -a "$LIVE_STATE/." "$S1/"
out=$(STATE="$S1" CRON_FILE="$T/nocron" timeout 120 bash "$H" status 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
check "status не прервался (есть итоговая строка)" grep -qE 'Критичных проблем нет|Есть проблемы' <<<"$out"
check "status без systemd/ufw -> rc=1" test "$rc" = 1
check "status: нет вывода die/ERR" bash -c "! grep -q 'ОШИБКА' <<<\"\$1\"" _ "$out"
check "status: 17+ строк проверок" test "$(grep -cE '(✓|✗|!)' <<<"$out")" -ge 17

echo "== status (живая установка + заглушки systemctl/ufw/fail2ban/sshd)"
: > "$T/cron.ok"
out=$(PATH="$STUBS:$PATH" STATE="$S1" CRON_FILE="$T/cron.ok" timeout 120 bash "$H" status 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
check "status со всеми зелёными службами -> rc=0" test "$rc" = 0
check "status: fail2ban banned=2" grep -q 'забанено сейчас: 2 (всего: 7)' <<<"$out"
check "status: UFW порты перечислены" grep -q 'разрешено: 22/tcp 443/tcp 8080/tcp 8443/tcp' <<<"$out"

echo "== status: подписка 2096 наружу -> ✗"
python3 -c 'import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",2096));s.listen();time.sleep(30)' & lp=$!
sleep 1
out=$(PATH="$STUBS:$PATH" STATE="$S1" CRON_FILE="$T/cron.ok" bash "$H" status 2>&1); rc=$?
kill "$lp" 2>/dev/null; wait "$lp" 2>/dev/null
check "2096 на 0.0.0.0 -> ✗ и rc=1" bash -c "grep -q 'подписка 2096 слушает наружу' <<<\"\$1\" && [ $rc = 1 ]" _ "$out"

echo "== backup"
B="$T/b"; mkdir -p "$B"; cp -a "$LIVE_STATE/keys" "$LIVE_STATE/panel.env" "$B/"; echo 'X=1' > "$B/config.env"; chmod 700 "$B"
out=$(STATE="$B" bash "$H" backup 2>&1); rc=$?; echo "    $out"
f=$(ls "$B"/backup/vpn-*.tgz 2>/dev/null | head -1)
check "backup rc=0 и печатает путь" bash -c "[ $rc = 0 ] && grep -q 'Бэкап: $B/backup/vpn-' <<<\"\$1\"" _ "$out"
check "имя vpn-YYYY-mm-dd-HHMM.tgz" bash -c "basename '$f' | grep -qE '^vpn-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}\.tgz$'"
check "права 600" test "$(stat -c %a "$f")" = 600
check "состав: x-ui.db keys/ panel.env config.env" bash -c "l=\$(tar -tzf '$f'); for x in x-ui.db keys/reality.json panel.env config.env; do grep -qx \"\$x\" <<<\"\$l\" || exit 1; done"
mkdir -p "$T/x"; tar -xzf "$f" -C "$T/x" x-ui.db
check "копия базы integrity ok" test "$(sqlite3 "$T/x/x-ui.db" 'PRAGMA integrity_check;')" = ok
check "копия базы содержит inbounds" test "$(sqlite3 "$T/x/x-ui.db" 'select count(*) from inbounds;')" -ge 1
check "quiet: ничего не печатает" test -z "$(STATE="$B" bash "$H" backup quiet 2>&1)"
for i in $(seq -w 1 20); do : > "$B/backup/vpn-2020-01-$i-0300.tgz"; done
: > "$B/backup/x-ui-2020-01-01-0000.db"
head -c 2000000 /dev/zero | tr '\0' 'a' > "$B/backup/cron.log"
STATE="$B" bash "$H" backup quiet; rc=$?
check "ротация: осталось 14 vpn-*.tgz" test "$(ls "$B"/backup/vpn-*.tgz | wc -l)" = 14
check "ротация: самые старые удалены, новый на месте" bash -c "[ ! -e '$B/backup/vpn-2020-01-01-0300.tgz' ] && [ -e '$B/backup/vpn-2020-01-20-0300.tgz' ] && [ -e '$f' ]"
check "чужие файлы (x-ui-*.db) не тронуты" test -e "$B/backup/x-ui-2020-01-01-0000.db"
check "cron.log > 1МБ урезан" test "$(stat -c %s "$B/backup/cron.log")" -lt 1048576
cnt_before=$(ls "$B"/backup/ | sort | md5sum)
head -c 4096 /dev/urandom > "$T/broken.db"
out=$(STATE="$B" XUI_DB="$T/broken.db" bash "$H" backup 2>&1); rc=$?; echo "    $out"
check "битая база -> rc!=0, старые бэкапы не удалены" bash -c "[ $rc != 0 ] && [ \"\$(ls '$B'/backup/ | sort | md5sum)\" = '$cnt_before' ]"
out=$(STATE="$B" XUI_DB="$T/nope.db" bash "$H" backup 2>&1); rc=$?
check "нет базы -> rc!=0" test "$rc" != 0

echo "== cron"
CF="$T/cron.d/vpn-setup-backup"
STATE="$B" CRON_FILE="$CF" bash "$H" cron >/dev/null 2>&1 || true
c1=$(cat "$CF" 2>/dev/null); STATE="$B" CRON_FILE="$CF" bash "$H" cron; c2=$(cat "$CF")
echo "$c2" | sed 's/^/    /'
check "cron: файл создан, 644" test "$(stat -c %a "$CF")" = 644
check "cron: строка 03:xx root bash STATE/install.sh backup quiet >> cron.log" \
  grep -qE "^[0-9]{1,2} 3 \* \* \* root bash $B/install.sh backup quiet >> $B/backup/cron.log 2>&1\$" "$CF"
check "cron: PATH задан" grep -q '^PATH=/usr/local/sbin' "$CF"
check "cron: идемпотентно (минута сохраняется)" test "$c1" = "$c2"
STATE="$B" CRON_FILE="$CF" bash "$H" uncron
check "cron: удалён" test ! -e "$CF"

echo "== links"
L="$T/l"; mkdir -p "$L"; cp -a "$LIVE_STATE/links.txt" "$L/"; mkdir -p "$L/qr"; : > "$L/qr/stale.png"
out=$(STATE="$L" bash "$H" links 2>&1); rc=$?
nl=$(grep -c '^vless://' "$L/links.txt")
check "links: rc=0, все ссылки выведены ($nl)" bash -c "[ $rc = 0 ] && [ \"\$(grep -c '^vless://' <<<\"\$1\")\" = $nl ]" _ "$out"
check "links: заголовки пользователей" bash -c "grep -q '=== HOME_PC ===' <<<\"\$1\" && grep -q '=== Lusya ===' <<<\"\$1\"" _ "$out"
check "links: QR пересозданы ($nl), устаревший удалён" bash -c "[ \$(ls '$L/qr' | wc -l) = $nl ] && [ ! -e '$L/qr/stale.png' ]"
check "links: имена QR безопасные, права 600" bash -c "ls '$L/qr' | grep -vqE '^[A-Za-z0-9_-]+\.png$' && exit 1; [ \"\$(stat -c %a '$L'/qr/*.png | sort -u)\" = 600 ]"
out=$(STATE="$L" bash "$H" links Lusya 2>&1); rc=$?
check "links Lusya: только её ссылки" bash -c "[ $rc = 0 ] && ! grep -q HOME_PC <<<\"\$1\" && [ \"\$(grep -c '^vless://' <<<\"\$1\")\" = 3 ]" _ "$out"
check "links Lusya: QR других не удалены" test "$(ls "$L/qr" | wc -l)" = "$nl"
STATE="$L" bash "$H" links Nobody >/dev/null 2>&1; check "links Nobody -> rc!=0" test $? != 0
STATE="$L" bash "$H" links 'a;b' >/dev/null 2>&1; check "links 'a;b' -> rc!=0" test $? != 0

# ---------- фейковое дерево для uninstall ----------
mkfake(){ # $1 = корень
  local F="$1"
  mkdir -p "$F/usr/local/x-ui/bin" "$F/etc/x-ui" "$F/etc/systemd/system" "$F/usr/bin" "$F/var/log/x-ui" "$F/etc/cron.d" "$F/root/vpn-setup/keys" "$F/root/vpn-setup/backup" "$F/root/vpn-setup/qr"
  echo bin > "$F/usr/local/x-ui/x-ui"; echo '{}' > "$F/usr/local/x-ui/bin/config.json"
  sqlite3 "$F/etc/x-ui/x-ui.db" 'create table inbounds(id int); insert into inbounds values(1);'
  echo unit > "$F/etc/systemd/system/x-ui.service"; echo cli > "$F/usr/bin/x-ui"; echo log > "$F/var/log/x-ui/a.log"
  echo '0 3 * * * root true' > "$F/etc/cron.d/vpn-setup-backup"
  echo secret > "$F/root/vpn-setup/keys/reality.json"; echo 'P_PORT=1' > "$F/root/vpn-setup/panel.env"
  printf '### A\nvless://x@1.2.3.4:443?a=b#R-A\n' > "$F/root/vpn-setup/links.txt"
  echo other > "$F/etc/cron.d/keepme"
}
fenv(){ # печатает env для фейкового дерева
  local F="$1"
  echo "STATE=$F/root/vpn-setup XUI_DIR=$F/usr/local/x-ui XUI_DB=$F/etc/x-ui/x-ui.db XUI_ETC=$F/etc/x-ui XUI_LOG=$F/var/log/x-ui XUI_UNIT=$F/etc/systemd/system/x-ui.service XUI_CLI=$F/usr/bin/x-ui CRON_FILE=$F/etc/cron.d/vpn-setup-backup FINAL_BACKUP_DIR=$F/root PATH=$STUBS:$PATH"
}
listing(){ find "$1" -printf '%p %s %m\n' | sort; }
run_un(){ local F="$1"; shift; local e; e=$(fenv "$F")
  case "$e" in *"STATE=/root/vpn-setup "*) echo "ОТКАЗ: живой STATE"; return 99;; esac
  # shellcheck disable=SC2086
  env $e "$@" setsid -w bash "$H" uninstall </dev/null 2>&1
}

echo "== uninstall: отказ без подтверждения"
F="$T/f1"; mkfake "$F"; listing "$F" > "$T/f1.before"; : > "$CALLS_LOG"
out=$(run_un "$F"); rc=$?; echo "$out" | tail -2 | sed 's/^/    /'
check "без подтверждения -> rc!=0" test "$rc" != 0
check "без подтверждения -> ничего не изменено" diff -q "$T/f1.before" <(listing "$F")
check "без подтверждения -> systemctl/ufw не вызывались" bash -c "! grep -qE '^(systemctl|ufw) ' '$CALLS_LOG'"
out=$(run_un "$F" UNINSTALL_CONFIRM=no); rc=$?
check "UNINSTALL_CONFIRM=no -> отказ" bash -c "[ $rc != 0 ] && diff -q '$T/f1.before' <(find '$F' -printf '%p %s %m\n' | sort) >/dev/null"
e=$(fenv "$F")
# shellcheck disable=SC2086
out=$(printf 'нет\n' | script -qec "env $e bash '$H' uninstall" /dev/null 2>&1); rc=$?
check "ввод 'нет' на tty -> отказ, ничего не изменено" bash -c "grep -q 'удаление отменено' <<<\"\$1\" && diff -q '$T/f1.before' <(find '$F' -printf '%p %s %m\n' | sort) >/dev/null" _ "$out"

echo "== uninstall: DRY_RUN=1"
: > "$CALLS_LOG"
out=$(run_un "$F" DRY_RUN=1); rc=$?; echo "$out" | grep DRY | sed 's/^/    /'
check "DRY_RUN rc=0" test "$rc" = 0
check "DRY_RUN: файлы не изменены" diff -q "$T/f1.before" <(listing "$F")
check "DRY_RUN: финального бэкапа нет" bash -c "! ls '$F'/root/vpn-setup-final-* >/dev/null 2>&1"
check "DRY_RUN: systemctl/ufw не вызывались" bash -c "! grep -qE '^(systemctl|ufw) ' '$CALLS_LOG'"
check "DRY_RUN: показаны все шаги" bash -c "for w in 'systemctl disable --now' 'rm -rf -- $F/usr/local/x-ui' 'rm -rf -- $F/etc/x-ui' 'rm -f $F/etc/cron.d' 'ufw --force delete allow 8443/tcp' 'mv -- $F/root/vpn-setup'; do grep -qF \"\$w\" <<<\"\$1\" || { echo \"нет: \$w\"; exit 1; }; done" _ "$out"

echo "== uninstall: реальное удаление фейкового дерева (fallback ufw)"
: > "$CALLS_LOG"
out=$(run_un "$F" UNINSTALL_CONFIRM=yes); rc=$?; echo "$out" | sed 's/^/    /'
check "uninstall rc=0" test "$rc" = 0
check "XUI_DIR, /etc/x-ui, unit, cli, log удалены" bash -c "for p in usr/local/x-ui etc/x-ui etc/systemd/system/x-ui.service usr/bin/x-ui var/log/x-ui; do [ ! -e '$F/'\$p ] || exit 1; done"
check "cron бэкапа удалён, чужой cron цел" bash -c "[ ! -e '$F/etc/cron.d/vpn-setup-backup' ] && [ -e '$F/etc/cron.d/keepme' ]"
check "STATE перемещён в *.removed-<дата>, 700, секреты на месте" bash -c "d=\$(ls -d '$F'/root/vpn-setup.removed-*) && [ ! -e '$F/root/vpn-setup' ] && [ \$(stat -c %a \"\$d\") = 700 ] && [ -s \"\$d/keys/reality.json\" ]"
check "финальный бэкап в FINAL_BACKUP_DIR, 600, с базой и ключами" bash -c "f=\$(ls '$F'/root/vpn-setup-final-*.tgz) && [ \$(stat -c %a \"\$f\") = 600 ] && tar -tzf \"\$f\" | grep -qx x-ui.db && tar -tzf \"\$f\" | grep -qx keys/reality.json"
check "systemctl disable --now + daemon-reload" bash -c "grep -qx 'systemctl disable --now x-ui.service' '$CALLS_LOG' && grep -qx 'systemctl daemon-reload' '$CALLS_LOG'"
check "ufw delete только для 443/8443/8080, не 22" bash -c "[ \$(grep -c '^ufw --force delete allow' '$CALLS_LOG') = 3 ] && ! grep -q 'allow 22/tcp' '$CALLS_LOG'"
check "SSH/sysctl не тронуты (нет вызовов restart ssh)" bash -c "! grep -qE 'restart|reload ssh|sysctl' '$CALLS_LOG'"
check "сводка печатает откат sysctl/ssh" bash -c "grep -q '90-vpn.conf' <<<\"\$1\" && grep -q '00-hardening.conf' <<<\"\$1\"" _ "$out"

echo "== uninstall: firewall_remove_ports из другого модуля + порт SSH защищён"
F="$T/f2"; mkfake "$F"; : > "$CALLS_LOG"
out=$(run_un "$F" UNINSTALL_CONFIRM=yes DEFINE_FW=1 PORT_XHTTP=22); rc=$?
check "rc=0" test "$rc" = 0
check "вызван firewall_remove_ports 443 8443 (22 = SSH пропущен)" grep -qx 'firewall_remove_ports 443 8443' "$CALLS_LOG"
check "ufw напрямую не вызывался" bash -c "! grep -q '^ufw ' '$CALLS_LOG'"

echo "== uninstall: повторный запуск по уже удалённому (идемпотентность)"
: > "$CALLS_LOG"
out=$(run_un "$F" UNINSTALL_CONFIRM=yes); rc=$?
check "повторно: rc=0, без падения" test "$rc" = 0

echo "== help"
out=$(bash "$H" help); check "help перечисляет все команды" bash -c "for w in harden-ssh 'sni [ДОМЕН]' status 'links [ИМЯ]' backup uninstall help; do grep -qF \"\$w\" <<<\"\$1\" || exit 1; done" _ "$out"

echo "== живая установка не изменена"
check "live: /usr/local/x-ui, /etc/x-ui, /root/vpn-setup, /etc/cron.d без изменений" diff "$T/live.before" <(snap_live)

echo; echo "ИТОГО: PASS=$PASS FAIL=$FAILN"
[ "$FAILN" = 0 ]
