#!/usr/bin/env bash
# check-server.sh — проверка нового сервера С ДОМАШНЕГО ПК (MobaXterm → Start local terminal), VPN выключен.
#   bash check-server.sh IP_СЕРВЕРА [ПОРТ]
# Шаг 1 проверяет SSH сам. Шаг 2 просит запустить на сервере: bash install.sh precheck [ПОРТ]
IP="${1:-}"; PORT="${2:-8080}"
[ -n "$IP" ] || { echo "Использование: bash check-server.sh IP_СЕРВЕРА [ПОРТ]"; exit 2; }
ok(){ printf '\033[1;32m%s\033[0m\n' "$*"; }; bad(){ printf '\033[1;31m%s\033[0m\n' "$*"; }

echo "== Шаг 1/2: SSH до $IP (3 попытки)"
command -v curl >/dev/null 2>&1 || { echo "нужен curl"; exit 2; }
n=0
for i in 1 2 3; do
  # curl есть везде (в т.ч. в MobaXterm); 'timeout' там может отсутствовать
  b=$(curl -s --max-time 6 "telnet://$IP:22" </dev/null 2>/dev/null | tr -d '\r' | head -n 1 | cut -c1-40)
  case "$b" in SSH-*) echo "  $i: $b"; n=$((n+1));; *) echo "  $i: нет ответа";; esac
  sleep 2
done
if [ "$n" = 0 ]; then
  bad "ВЕРДИКТ: SSH-данные до $IP не доходят — твой провайдер режет этот IP."
  echo "Дальше пробовать бессмысленно: проси у хостера другой IP/локацию или бери другого хостера."
  echo "(Проверь, что VPN выключен — иначе тест неточный.)"
  exit 1
fi
[ "$n" = 3 ] && ok "  SSH проходит." || echo "  SSH проходит не всегда ($n из 3) — IP «моргает», это плохой знак."

echo
echo "== Шаг 2/2: передача данных (как у VPN)"
echo "Зайди на сервер и запусти:  bash install.sh precheck $PORT"
echo "(до установки: bash <(curl -fsSL https://raw.githubusercontent.com/beepbeepgreench/hello-ui-bye-rkn/main/install.sh) precheck $PORT)"
read -r -p "Когда на сервере появится «Тестовый сервер запущен», нажми Enter… " _
good=0
for i in 1 2; do
  r=$(curl -s -o /dev/null --max-time 20 -w '%{size_download} %{http_code}' "http://$IP:$PORT/f.bin")
  echo "  попытка $i: получено ${r% *} байт, код ${r#* }"
  [ "${r% *}" = 300000 ] && good=$((good+1))
  sleep 2
done
echo
if [ "$good" = 2 ]; then
  ok "ВЕРДИКТ: IP рабочий — ставь скрипт:  bash install.sh"
  exit 0
elif [ "$good" = 1 ]; then
  bad "ВЕРДИКТ: нестабильно (1 из 2). Повтори проверку через 10 минут; если снова так — IP лучше не использовать."
  exit 1
else
  bad "ВЕРДИКТ: данные не доходят (или обрываются) — провайдер режет этот IP. Ставить VPN бессмысленно."
  echo "Если получено 0 байт и код 000 — проверь, что на сервере запущен precheck и порт $PORT открыт."
  exit 1
fi
