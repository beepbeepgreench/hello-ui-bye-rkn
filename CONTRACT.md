# Контракт модулей (для разработки)

`install.sh` собирается `build.sh` из `install.sh.in` + модулей:
- `lib/ssh.sh`  — bash-функции SSH/firewall/fail2ban (вставляется целиком в install.sh)
- `lib/ops.sh`  — bash-функции status/backup/uninstall/links (вставляется целиком)
- `lib/sni.py`  — python3 CLI подбора/проверки сайта маскировки (на сервере пишется в $STATE/sni.py)
- `lib/provision.py` — создание inbound/клиентов через API панели (пишется в $STATE/provision.py)

## Общая среда исполнения install.sh (уже определено ДО модулей)
- `set -Eeuo pipefail`, `trap 'die ...' ERR` — ЛЮБАЯ ненулевая команда вне if/||/&& убивает скрипт.
  Запрещено: `cmd | grep -q` (SIGPIPE→ошибка с pipefail), `x=$(падающая | awk)` без `|| true`,
  голое `[ ... ] && cmd` последней строкой функции.
- Функции-хелперы: `step "текст"`, `warn "текст"`, `die "текст"`, `ask VAR "вопрос" "дефолт"` (читает /dev/tty).
- Цвета: `$c_ok $c_err $c_warn $c_no`.
- Переменные: `STATE=/root/vpn-setup` (700), `ARCH` (amd64|arm64), `XRAY_BIN`, `PORT_REALITY PORT_SUDOKU PORT_XHTTP`,
  `$STATE/panel.env` (P_USER P_PASS P_PORT P_PATH), `$STATE/api.token`, `$STATE/config.env` (сохранённые настройки),
  `$STATE/keys/` (секреты provision.py, links.txt), `$STATE/qr/`, `$STATE/backup/`.
- Панель: `http://127.0.0.1:${P_PORT}/${P_PATH}`, API: Bearer-токен, ответы `{"success":bool,"msg":..,"obj":..}`.
- Все сообщения пользователю — на русском. shellcheck -S warning — без замечаний.
- Ubuntu 22.04/24.04/26.04. SSH на 24.04+ — socket-activated (`ssh.socket`), `/run/sshd` может отсутствовать.
