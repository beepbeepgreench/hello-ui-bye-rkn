#!/usr/bin/env bash
# Тесты меню и итогов установки (install.sh собран через build.sh).
# Нужна песочница с установленным vpn-setup в /root/vpn-setup и запущенной панелью (как в tests/ops);
# systemctl/ufw — через шимы: SHIM=/путь/к/шимам bash tests/menu/run.sh
# FULL=1 — ещё и долгие прогоны повторной установки (≈1–2 мин каждый).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
INST="$ROOT/install.sh"; DRV="$HERE/pty_drive.py"
PASS=0; FAILN=0
ok(){ echo "PASS  $*"; PASS=$((PASS+1)); }
bad(){ echo "FAIL  $*"; FAILN=$((FAILN+1)); }
has(){ grep -q -- "$2" "$1"; }
T=$(mktemp -d /tmp/menu-test.XXXXXX); trap 'rm -rf "$T"' EXIT
[ -n "${SHIM:-}" ] && export PATH="$SHIM:$PATH"
[ -f "$INST" ] || { echo "нет $INST — сначала bash build.sh"; exit 2; }

echo "== static"
bash -n "$INST" && ok "bash -n install.sh" || bad "bash -n install.sh"
shellcheck -S warning "$INST" && ok "shellcheck install.sh" || bad "shellcheck install.sh"

echo "== меню: сервер не настроен (пустой STATE)"
E="$T/empty"; mkdir -p "$E"
printf '%s\t%s\n' 'Выбери пункт' '3\n' 'назад в меню' '\n' 'Выбери пункт' '0\n' \
  | STATE="$E" python3 "$DRV" 30 "$T/a.out" -- bash "$INST"; rc=$?
[ "$rc" = 0 ] && ok "меню (не настроен): выход по 0, код 0" || bad "меню (не настроен): код $rc"
has "$T/a.out" 'НЕ настроен' && ok "заголовок: VPN не настроен" || bad "нет заголовка «НЕ настроен»"
has "$T/a.out" '1) Установить VPN' && ok "пункт «Установить VPN»" || bad "нет пункта «Установить VPN»"
has "$T/a.out" 'Использование:' && ok "пункт 3 → справка" || bad "пункт 3 не показал справку"
has "$T/a.out" '0/9 Проверки' && bad "меню не должно запускать установку само" || ok "установка не запускалась"

echo "== без терминала / с переменными / с командой — сразу команда, без меню"
STATE="$E" bash "$INST" </dev/null >"$T/c.out" 2>&1; rc=$?
{ has "$T/c.out" '0/9 Проверки' && ! has "$T/c.out" 'Выбери пункт'; } && ok "без tty: сразу установка (код $rc)" || bad "без tty: $(head -c 300 "$T/c.out")"
printf '' | STATE="$E" USERS=test1 python3 "$DRV" 30 "$T/d.out" -- bash "$INST"; rc=$?
{ has "$T/d.out" '0/9 Проверки' && ! has "$T/d.out" 'Выбери пункт'; } && ok "tty + USERS=: сразу установка" || bad "tty + USERS=: меню или нет установки"
printf '' | STATE="$E" python3 "$DRV" 20 "$T/v.out" -- bash "$INST" version; rc=$?
{ [ "$rc" = 0 ] && has "$T/v.out" 'vpn-setup v' && ! has "$T/v.out" 'Выбери пункт'; } && ok "tty + аргумент version: без меню" || bad "version: код $rc"
printf '' | VPN_SETUP_MENU=0 STATE="$E" python3 "$DRV" 30 "$T/m0.out" -- bash "$INST"; rc=$?
has "$T/m0.out" '0/9 Проверки' && ok "VPN_SETUP_MENU=0: без меню" || bad "VPN_SETUP_MENU=0 не отключил меню"
STATE="$E" bash "$INST" site </dev/null >"$T/s.out" 2>&1; rc=$?
if grep -q 'cmd_site()' "$INST"; then ok "site: модуль шаблонов есть (cmd_site)"
else { [ "$rc" != 0 ] && has "$T/s.out" 'модулем шаблонов'; } && ok "site без модуля: понятная ошибка" || bad "site: $(cat "$T/s.out")"; fi

echo "== проверка домена: недоступный DNS-over-HTTPS → ошибка, не зависание"
HTTPS_PROXY=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 STATE="$E" timeout 60 bash "$INST" _domain_check example.org 203.0.113.10 >"$T/g.out" 2>&1; rc=$?
{ [ "$rc" != 0 ] && [ "$rc" != 124 ] && has "$T/g.out" 'DNS'; } && ok "_domain_check без DNS: код $rc, причина про DNS" || bad "_domain_check: код $rc $(cat "$T/g.out")"
STATE="$E" bash "$INST" _domain_check my-vpn.example 203.0.113.10 >"$T/g2.out" 2>&1; rc=$?
{ [ "$rc" != 0 ] && has "$T/g2.out" 'vpn'; } && ok "_domain_check: имя с vpn отклонено" || bad "_domain_check vpn: $rc"

if [ -f /root/vpn-setup/panel.env ] && [ -x /usr/local/x-ui/x-ui ]; then
  echo "== меню: сервер настроен (песочница /root/vpn-setup)"
  install -m 700 "$INST" /root/vpn-setup/install.sh
  . /root/vpn-setup/panel.env
  printf '%s\t%s\n' 'Выбери пункт' '4\n' 'назад в меню' '\n' 'Выбери пункт' '3\n' 'Имя пользователя' 'BOB\n' \
    'назад в меню' '\n' 'Выбери пункт' '7\n' 'назад в меню' '\n' 'Выбери пункт' '0\n' \
    | python3 "$DRV" 120 "$T/b.out" -- bash /root/vpn-setup/install.sh; rc=$?
  [ "$rc" = 0 ] && ok "меню (настроен): код 0" || bad "меню (настроен): код $rc"
  has "$T/b.out" 'vpn-setup v1' && has "$T/b.out" 'Состояние:' && ok "заголовок: версия и состояние" || bad "нет заголовка"
  grep -Eq 'Состояние: (✓|!|✗)' "$T/b.out" && ok "сводка состояния посчитана" || bad "сводка состояния не посчитана"
  has "$T/b.out" '12) Удалить VPN' && ok "полный список пунктов" || bad "нет пункта 12"
  has "$T/b.out" "Пароль: $P_PASS" && ok "пункт 4 → вход в панель (с паролем, это терминал)" || bad "пункт 4 не показал панель"
  has "$T/b.out" '=== BOB ===' && ! has "$T/b.out" '=== Lusya ===' && ok "пункт 3 → ссылки одного пользователя" || bad "пункт 3: ссылки BOB"
  has "$T/b.out" 'Сначала включи свой домен' && ok "пункт 7 без домена: подсказка" || bad "пункт 7 без домена"

  if [ "${FULL:-0}" = 1 ]; then
    echo "== повторная установка без терминала + DOMAIN= с плохим именем → установка завершается"
    DOMAIN=myvpn-test.com vpn-setup </dev/null >"$T/f.out" 2>&1; rc=$?
    [ "$rc" = 0 ] && ok "DOMAIN= (плохое имя): код 0" || bad "DOMAIN= (плохое имя): код $rc"
    has "$T/f.out" 'ГОТОВО С ЗАМЕЧАНИЯМИ' && ok "итог: ГОТОВО С ЗАМЕЧАНИЯМИ" || bad "нет ГОТОВО С ЗАМЕЧАНИЯМИ"
    has "$T/f.out" 'продолжаю без своего домена' && ok "понятная причина и продолжение" || bad "нет «продолжаю без своего домена»"
    grep -q "^DOMAIN=''" /root/vpn-setup/config.env && ok "config: DOMAIN пустой" || bad "config: DOMAIN записан"
    has "$T/f.out" "$P_PASS" && bad "без терминала пароль панели попал в вывод" || ok "без терминала пароль не печатается"
    has "$T/f.out" 'Адрес в браузере' && has "$T/f.out" 'README.txt' && ok "без терминала: блок панели с отсылкой к README.txt" || bad "нет блока панели"
    grep -q 'vless://' /root/vpn-setup/README.txt && grep -q "$P_PASS" /root/vpn-setup/README.txt && ok "README.txt: пароль и ссылки в одном файле" || bad "README.txt неполный"

    echo "== повторная установка в терминале: итог с паролем и вопросом про ссылки"
    { [ -s /root/.ssh/authorized_keys ] || printf '%s\t%s\n' 'SSH-ключ' '\n'
      printf '%s\t%s\n' 'Показать ссылки' 'y\n'; } \
      | python3 "$DRV" 600 "$T/t.out" -- bash /root/vpn-setup/install.sh install; rc=$?
    [ "$rc" = 0 ] && ok "install в tty: код 0" || bad "install в tty: код $rc"
    has "$T/t.out" "Пароль: $P_PASS" && ok "в терминале пароль панели показан" || bad "в терминале нет пароля"
    has "$T/t.out" 'вкладка SFTP' && ok "подсказка про SFTP и README.txt" || bad "нет подсказки SFTP"
    has "$T/t.out" '=== HOME_PC ===' && ok "ответ y → ссылки показаны" || bad "ссылки не показаны"
    has "$T/t.out" 'Свой домен для маскировки' && bad "повторная установка не должна спрашивать домен" || ok "повторная установка: домен не спрашивается"
  fi
else
  echo "(песочницы с установленным vpn-setup нет — тесты настроенного меню пропущены)"
fi

echo "== итог: PASS $PASS, FAIL $FAILN"
[ "$FAILN" = 0 ]
