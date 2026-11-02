#!/usr/bin/env bash
# shellcheck disable=SC2034  # c_* читаются внутри модуля
# Тесты lib/domain.sh. Каталоги nginx/www/letsencrypt — во временной папке; DoH, systemctl, apt — заглушки.
# Блок «живой nginx» выполняется, только если в системе есть nginx (иначе SKIP).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd); MOD="$ROOT/lib/domain.sh"
PASS=0; FAIL=0; SKIP=0; FAILED=()
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
chmod 755 "$T"   # воркеры nginx (www-data) должны читать сайт в живом тесте
mkdir -p "$T/stub" "$T/state"
export DOMAIN_NGINX_DIR="$T/nginx" DOMAIN_WWW_ROOT="$T/www" DOMAIN_LE_DIR="$T/le" DOMAIN_SELF_DIR="$T/self" STATE="$T/state"
cat > "$T/stub/systemctl" <<'EOF'
#!/bin/sh
echo "systemctl $*" >> "$STUB_LOG"; exit 0
EOF
cat > "$T/stub/apt-get" <<'EOF'
#!/bin/sh
echo "apt-get $*" >> "$STUB_LOG"; exit 0
EOF
chmod +x "$T/stub/"*; export STUB_LOG="$T/log"; : > "$T/log"

mod(){ # функция модуля в среде install.sh (set -Eeuo + ERR trap → die); DOH_A/DOH_AAAA — ответы DNS
  ( set -Eeuo pipefail
    c_ok=""; c_err=""; c_warn=""; c_no=""
    step(){ echo "STEP $*"; }; warn(){ echo "WARN $*"; }; die(){ echo "DIE $*"; exit 1; }
    trap 'die "ERR-TRAP line $LINENO: $BASH_COMMAND"' ERR
    # shellcheck source=/dev/null
    source "$MOD"
    if [ -n "${DOH_MODE:-}" ]; then
      _domain_doh(){ case "$DOH_MODE" in fail) return 1;; esac
        if [ "$2" = A ]; then printf '%s\n' ${DOH_A:-}; else printf '%s\n' ${DOH_AAAA:-}; fi; }
    fi
    _ops_mark(){ echo "MARK $1 $2"; }; _ops_listeners(){ ss -Htln "sport = :$1" 2>/dev/null | awk '{print $4}' || true; }
    "$@" ) 2>&1
}
ok(){ PASS=$((PASS+1)); echo "PASS  $1"; }
bad(){ FAIL=$((FAIL+1)); FAILED+=("$1"); echo "FAIL  $1"; echo "      out: ${OUT//$'\n'/ | }"; }
check(){ local name="$1"; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }
has(){ grep -qF -- "$2" <<<"$1"; }

# ---------------- имя ----------------
OUT=$(mod domain_normalize "HTTPS://LenaFoto.NET/path/"); check "normalize: схема/путь/регистр" [ "$OUT" = lenafoto.net ]
OUT=$(mod domain_normalize "фото-заметки.рф"); check "normalize: IDN → punycode" has "$OUT" "xn--"
OUT=$(mod domain_normalize "bad_name.com"); rc=$?; check "normalize: подчёркивание отвергнуто" [ "$rc" != 0 ]
OUT=$(mod domain_normalize "localhost"); rc=$?; check "normalize: без зоны отвергнуто" [ "$rc" != 0 ]
OUT=$(mod domain_normalize "1.2.3.4"); rc=$?; check "normalize: IP отвергнут" [ "$rc" != 0 ]
for n in myvpn.com wgtrojan.online fastproxy.net best-xray.org tunnel.photo.de vless.eu; do
  OUT=$(mod domain_name_check "$n"); check "name: $n отвергнут (VPN-имя)" has "$OUT" "DIE домен $n"
done
OUT=$(mod domain_name_check lenafoto.net); check "name: нейтральное имя проходит без замечаний" [ -z "$OUT" ]
OUT=$(mod domain_name_check lenafoto.ru); check "name: .ru → предупреждение, не отказ" bash -c '[[ "$1" == WARN* ]] && [[ "$1" != *DIE* ]]' _ "$OUT"
OUT=$(mod domain_name_check xn--80aswg.xn--p1ai); check "name: .рф → предупреждение" has "$OUT" "WARN"
OUT=$(mod domain_name_check proxima.com); check "name: proxima (prox) — консервативно отвергнут" has "$OUT" "DIE"

# ---------------- DNS ----------------
OUT=$(DOH_MODE=ok DOH_A="203.0.113.10" mod domain_dns_check lenafoto.net 203.0.113.10); check "dns: A = IP сервера → ok" has "$OUT" "DNS: lenafoto.net → 203.0.113.10"
OUT=$(DOH_MODE=ok DOH_A="198.51.100.7" mod domain_dns_check lenafoto.net 203.0.113.10); check "dns: другой IP → отказ с подсказкой" has "$OUT" "Исправь A-запись"
OUT=$(DOH_MODE=ok DOH_A="203.0.113.10 198.51.100.7" mod domain_dns_check lenafoto.net 203.0.113.10); check "dns: лишняя A-запись → отказ" has "$OUT" "DIE"
OUT=$(DOH_MODE=ok DOH_A="" mod domain_dns_check lenafoto.net 203.0.113.10); check "dns: нет A-записи → инструкция" has "$OUT" "нет A-записи"
OUT=$(DOH_MODE=ok DOH_A="104.21.5.9" mod domain_dns_check lenafoto.net 203.0.113.10); check "dns: Cloudflare-прокси распознан" has "$OUT" "DNS only"
OUT=$(DOH_MODE=ok DOH_A="203.0.113.10" DOH_AAAA="2001:db8::1" mod domain_dns_check lenafoto.net 203.0.113.10); check "dns: AAAA → отказ (IPv6 выключен)" has "$OUT" "AAAA"
OUT=$(DOH_MODE=fail mod domain_dns_check lenafoto.net 203.0.113.10); check "dns: DoH недоступен → понятная ошибка" has "$OUT" "DOMAIN_SKIP_DNS=1"
OUT=$(DOMAIN_SKIP_DNS=1 DOH_MODE=fail mod domain_dns_check lenafoto.net 203.0.113.10); check "dns: DOMAIN_SKIP_DNS=1 → пропуск" has "$OUT" "пропущена"
OUT=$(mod domain_is_cloudflare 172.67.1.1 && echo Y); check "cf: 172.67.x — Cloudflare" has "$OUT" Y
OUT=$(mod domain_is_cloudflare 89.125.250.179 || echo N); check "cf: обычный IP — нет" has "$OUT" N

# ---------------- порт ----------------
OUT=$(DOMAIN_PORT=9555 mod domain_pick_port); check "port: сохранённый DOMAIN_PORT" [ "$OUT" = 9555 ]
OUT=$(mod domain_pick_port); check "port: свободный из 9443..9499" bash -c '[ "$1" -ge 9443 ] && [ "$1" -le 9499 ]' _ "$OUT"

# ---------------- сайты-маски (шаблоны lib/sites) ----------------
export DOMAIN_CRON_FILE="$T/cron.d-vpn-setup-site"
FX="$T/fx"; mkdir -p "$FX"
python3 - "$FX" <<'PY'
import json, sys, datetime as dt
fx = sys.argv[1]
r = {"USD":1,"EUR":0.92,"GBP":0.78,"CNY":7.1,"JPY":151.0,"CHF":0.88,"TRY":34.2,"KZT":492.0,"BYN":3.27,"RUB":96.5,"PLN":3.98,"AED":3.67}
json.dump({"result":"success","time_last_update_unix":1700000000,"rates":r}, open(fx+"/er.json","w"))
json.dump({"result":"error"}, open(fx+"/bad.json","w"))
t = dt.date.today()
for b in range(1, 31):
    d = t - dt.timedelta(days=b)
    v = {c: {"Nominal": 1, "Value": 96.5 / x} for c, x in r.items() if c != "RUB"}
    json.dump({"Valute": v}, open(f"{fx}/cbr-{d.year}-{d.month:02d}-{d.day:02d}.json", "w"))
PY
export RATES_URL="file://$FX/er.json" SEED_URL="file://$FX/cbr-{y}-{m}-{d}.json"
W="$T/www/lenafoto.net"
OUT=$(mod domain_site_list); check "site list: три шаблона card/status/rates" bash -c '[ "$(cut -d"|" -f1 <<<"$1" | tr "\n" " ")" = "card status rates " ]' _ "$OUT"
OUT=$(mod domain_site_deploy lenafoto.net bogus); check "site: неизвестный шаблон → отказ" has "$OUT" "DIE нет такого шаблона"
OUT=$(mod domain_decoy lenafoto.net)
check "card: index/work/404/robots/sitemap/favicon/style" bash -c 'for f in index.html work.html 404.html robots.txt sitemap.xml favicon.svg style.css; do [ -s "$1/$f" ] || exit 1; done' _ "$W"
check "card: маркер «card ХЭШ» + манифест" bash -c 'head -1 "$1/.vpn-setup-site" | grep -qE "^card [0-9a-f]{16}$" && grep -qx index.html "$1/.vpn-setup-site"' _ "$W"
check "card: .net → английский" grep -q '<html lang="en">' "$W/index.html"
check "card: незаменённых {{…}} нет" bash -c '! grep -rq "{{" "$1"' _ "$W"
check "card: почта на основном домене" grep -q 'mailto:[a-z]*@lenafoto.net' "$W/index.html"
check "card: даты изменения в прошлом (>10 дней)" bash -c '[ $(( $(date +%s) - $(stat -c %Y "$1") )) -gt 864000 ]' _ "$W/index.html"
check "card: нет слов vpn/proxy/xray/reality" bash -c '! grep -rqiE "vpn|proxy|xray|reality|x-ui" "$1" --exclude=.vpn-setup-site' _ "$W"
check "card: нет внешних ресурсов (src/href на http)" bash -c '! grep -rqE "(src|href)=\"https?://" "$1"' _ "$W"
check "card: cron не ставится" [ ! -e "$DOMAIN_CRON_FILE" ]
OUT=$(mod domain_site_deploy lenafoto.net card); check "card: повторный запуск — без пересборки" has "$OUT" "уже стоит"
cp "$W/index.html" "$T/i1"; rm -rf "$T/www/other.net"; mod domain_site_deploy other.net card >/dev/null
check "card: другой домен — другой сайт (имя/цвет)" bash -c '! cmp -s "$1" "$2"' _ "$T/i1" "$T/www/other.net/index.html"
OUT=$(mod domain_site_deploy shop.example.ru card); check "card: .ru → русский" grep -q '<html lang="ru">' "$T/www/shop.example.ru/index.html"
check "card: почта не на поддомене" grep -q '@example.ru' "$T/www/shop.example.ru/index.html"
echo "extra" > "$W/my-note.txt"
OUT=$(mod domain_site_deploy lenafoto.net status)
check "status: сайт заменён (history.html), старые файлы card удалены" bash -c '[ -s "$1/history.html" ] && [ ! -e "$1/work.html" ] && head -1 "$1/.vpn-setup-site" | grep -q "^status "' _ "$W"
check "status: чужой файл пользователя сохранён" [ -f "$W/my-note.txt" ]
check "status: status.json с цифрами, без IP" python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); assert {"updated","uptime_s","load","cpus","mem_pct","disk_pct","days"} <= set(s); assert "." not in "".join(str(x) for x in [s.get("ip","")])' "$W/data/status.json"
check "status: cron каждую минуту запускает collect.py" grep -qE '^\* \* \* \* \* root .*collect\.py .*/lenafoto\.net/data' "$DOMAIN_CRON_FILE"
check "status: collect.py лежит в STATE/site" [ -f "$T/state/site/collect.py" ]
python3 -I "$T/state/site/collect.py" "$W/data"
check "status: история по дням копится" python3 -c 'import json,sys; h=json.load(open(sys.argv[1])); assert sum(h["days"].values())>=2' "$W/data/status-history.json"
OUT=$(mod domain_site_deploy lenafoto.net rates)
check "rates: rates.json валидный (12 валют, история 30 дн.)" python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); assert len(j["usd"])==12 and len(j["hist"])>=15' "$W/data/rates.json"
check "rates: данные status удалены при смене" [ ! -e "$W/data/status.json" ]
check "rates: cron раз в час (fetch.py), status-cron заменён" bash -c 'grep -qE "^[0-9]+ \* \* \* \* root .*fetch\.py" "$1" && ! grep -q collect.py "$1"' _ "$DOMAIN_CRON_FILE"
cp "$W/data/rates.json" "$T/r1"
OUT=$(RATES_URL="file://$FX/bad.json" python3 -I "$T/state/site/fetch.py" "$W/data" 2>&1); rc=$?
check "rates: плохой ответ API → код 1, старый файл цел" bash -c '[ "$1" = 1 ] && cmp -s "$2" "$3"' _ "$rc" "$T/r1" "$W/data/rates.json"
OUT=$(RATES_URL="file://$FX/nope.json" python3 -I "$T/state/site/fetch.py" "$W/data" 2>&1); rc=$?
check "rates: API недоступен → код 1, старый файл цел" bash -c '[ "$1" = 1 ] && cmp -s "$2" "$3"' _ "$rc" "$T/r1" "$W/data/rates.json"
OUT=$(mod domain_site_deploy lenafoto.net card)
check "card снова: cron удалён, data удалена" bash -c '[ ! -e "$1" ] && [ ! -e "$2/data" ]' _ "$DOMAIN_CRON_FILE" "$W"
mod domain_site_deploy lenafoto.net status >/dev/null
PATH="$T/nb0:$T/stub:$PATH" mod domain_disable >/dev/null 2>&1
check "off: cron обновления данных сайта удалён" [ ! -e "$DOMAIN_CRON_FILE" ]
# свой сайт пользователя
mkdir -p "$T/www/own.net"; echo "my own site" > "$T/www/own.net/index.html"
OUT=$(mod domain_site_deploy own.net status); check "own: свой сайт не перезаписан" bash -c 'grep -qx "my own site" "$1/index.html" && [ ! -e "$1/.vpn-setup-site" ]' _ "$T/www/own.net"
check "own: сообщение «не трогаю»" has "$OUT" "не трогаю"
# заглушка прошлой версии (без маркера) заменяется
mkdir -p "$T/www/old.net/notes"; echo '<footer>© 2026 Old · written slowly, published rarely</footer>' > "$T/www/old.net/index.html"; echo x > "$T/www/old.net/notes/bike-wheel.html"
OUT=$(mod domain_site_deploy old.net card); check "legacy: старая заглушка заменена шаблоном" bash -c '[ -s "$1/work.html" ] && [ ! -d "$1/notes" ]' _ "$T/www/old.net"
# vpn-setup site (cmd_site) — require_installed/load_config/save_config из install.sh — заглушки
OUT=$(mod eval "require_installed(){ :; }; load_config(){ DOMAIN=lenafoto.net; SITE_TEMPLATE=rates; }; save_config(){ echo SAVED=\$SITE_TEMPLATE; }; cmd_site")
check "cmd_site: список с отметкой текущего" has "$OUT" "* rates"
OUT=$(mod eval "require_installed(){ :; }; load_config(){ DOMAIN=lenafoto.net; SITE_TEMPLATE=card; }; save_config(){ echo SAVED=\$SITE_TEMPLATE; }; cmd_site status")
check "cmd_site status: развёрнут и сохранён" bash -c 'grep -q "SAVED=status" <<<"$1" && head -1 "$2/.vpn-setup-site" | grep -q "^status "' _ "$OUT" "$W"
OUT=$(mod eval "require_installed(){ :; }; load_config(){ DOMAIN=; SITE_TEMPLATE=card; }; save_config(){ echo SAVED=\$SITE_TEMPLATE; }; cmd_site rates")
check "cmd_site без домена: только сохраняет выбор" bash -c 'grep -q "SAVED=rates" <<<"$1" && ! grep -q "сайт: шаблон" <<<"$1"' _ "$OUT"
OUT=$(mod eval "require_installed(){ :; }; load_config(){ DOMAIN=; }; save_config(){ :; }; cmd_site nope"); check "cmd_site: неизвестный → отказ" has "$OUT" "DIE нет такого шаблона"
# шаблоны из собранного install.sh (base64 tar.gz) раскрываются и работают
if [ -f "$ROOT/install.sh" ] && grep -q '^_domain_sites_payload' "$ROOT/install.sh"; then
  awk '/^_domain_sites_payload\(\)/{f=1;next} /^SITESEOF/{f=0} f' "$ROOT/install.sh" | base64 -d | { mkdir -p "$T/built"; tar -xzf - -C "$T/built"; }
  OUT=$(DOMAIN_SITES_SRC="$T/built" mod domain_site_deploy built.org rates)
  check "build: вшитые шаблоны распаковываются и собираются" bash -c '[ -s "$1/index.html" ] && [ -s "$1/data/rates.json" ]' _ "$T/www/built.org"
else
  SKIP=$((SKIP+1)); echo "SKIP  build: install.sh не собран"
fi
rm -f "$DOMAIN_CRON_FILE"

# ---------------- конфиг nginx (nginx-заглушка: проверка синтаксиса не нужна) ----------------
mkdir -p "$T/nb"; printf '#!/bin/sh\ncase "$1" in -v) echo "nginx version: nginx/%s" >&2;; esac\nexit 0\n' "${FAKE_NGINX_VER:-1.24.0}" > "$T/nb/nginx"; chmod +x "$T/nb/nginx"
mkdir -p "$T/nginx/sites-available" "$T/nginx/sites-enabled"; echo "server{}" > "$T/nginx/sites-available/default"; ln -s ../sites-available/default "$T/nginx/sites-enabled/default"
CONF="$T/nginx/sites-available/vpn-setup-domain.conf"
OUT=$(PATH="$T/nb:$T/stub:$PATH" mod domain_write_nginx lenafoto.net 9443 http)
check "nginx http: только :80 (ACME + 301), без TLS" bash -c 'grep -q "listen 80 default_server" "$1" && grep -q "acme-challenge" "$1" && grep -q "return 301 https://lenafoto.net" "$1" && ! grep -q ssl_certificate "$1"' _ "$CONF"
check "nginx: стандартный сайт выключен и это запомнено" bash -c '[ ! -e "$1/sites-enabled/default" ] && [ -f "$2/domain.default-disabled" ]' _ "$T/nginx" "$T/state"
OUT=$(PATH="$T/nb:$T/stub:$PATH" mod domain_write_nginx lenafoto.net 9443 full)
check "nginx full: TLS только на 127.0.0.1:9443" bash -c 'grep -q "listen 127.0.0.1:9443 ssl" "$1" && ! grep -qE "listen (0\.0\.0\.0:)?443|listen \[::\]" "$1"' _ "$CONF"
check "nginx full: TLS1.3 и сертификат Let's Encrypt" bash -c 'grep -q "TLSv1.3" "$1" && grep -q "/le/live/lenafoto.net/fullchain.pem" "$1"' _ "$CONF"
check "nginx 1.24: http2 в listen" grep -q "listen 127.0.0.1:9443 ssl http2" "$CONF"
printf '#!/bin/sh\ncase "$1" in -v) echo "nginx version: nginx/1.28.0" >&2;; esac\nexit 0\n' > "$T/nb/nginx"
OUT=$(PATH="$T/nb:$T/stub:$PATH" mod domain_write_nginx lenafoto.net 9443 full)
check "nginx 1.28: директива http2 on" bash -c 'grep -q "http2 on;" "$1" && ! grep -q "ssl http2" "$1"' _ "$CONF"
check "nginx: сайт включён симлинком" [ -L "$T/nginx/sites-enabled/vpn-setup-domain.conf" ]

# ---------------- сертификат ----------------
OUT=$(DOMAIN_CERT_MODE=selfsigned mod domain_cert lenafoto.net)
check "cert selfsigned: создан, SAN=домен" bash -c 'openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | grep -q "DNS:lenafoto.net"' _ "$T/self/lenafoto.net.crt"
OUT=$(mod domain_cert_paths lenafoto.net); check "cert paths: без LE-файла, но с selfsigned → selfsigned" has "$OUT" "$T/self/lenafoto.net.crt"
mkdir -p "$T/nocb"; for f in /usr/local/bin/* /usr/bin/* /bin/*; do b=${f##*/}; [ "$b" = certbot ] || [ -e "$T/nocb/$b" ] || ln -s "$f" "$T/nocb/$b" 2>/dev/null; done
OUT=$(PATH="$T/nocb" mod domain_cert lenafoto.net); check "cert LE: нет certbot → понятная ошибка" has "$OUT" "certbot не установлен"
printf '#!/bin/sh\necho "certbot $*" >> "$STUB_LOG"; exit 1\n' > "$T/stub/certbot"; chmod +x "$T/stub/certbot"
OUT=$(PATH="$T/stub:$PATH" mod domain_cert lenafoto.net); check "cert LE: отказ certbot → причины и команда повтора" has "$OUT" "vpn-setup domain lenafoto.net"
check "cert LE: webroot + без email + неинтерактивно" grep -q -- "certonly --webroot -w $T/www/_acme -d lenafoto.net --non-interactive --agree-tos --register-unsafely-without-email" "$T/log"
printf '#!/bin/sh\necho "certbot $*" >> "$STUB_LOG"; exit 0\n' > "$T/stub/certbot"
OUT=$(DOMAIN_CERT_MODE=staging PATH="$T/stub:$PATH" mod domain_cert lenafoto.net)
check "cert staging: флаг --staging" grep -q -- "--staging" "$T/log"
check "cert: deploy-hook перезагружает nginx" grep -q "systemctl reload nginx" "$T/le/renewal-hooks/deploy/vpn-setup-nginx.sh"

# ---------------- выключение ----------------
: > "$T/state/domain.nginx-installed"
OUT=$(PATH="$T/nb:$T/stub:$PATH" mod domain_disable)
check "off: наш конфиг и хук удалены, файлы сайта остались" bash -c '[ ! -e "$1/sites-available/vpn-setup-domain.conf" ] && [ ! -e "$1/sites-enabled/vpn-setup-domain.conf" ] && [ ! -e "$2" ] && [ -d "$3/lenafoto.net" ]' _ "$T/nginx" "$T/le/renewal-hooks/deploy/vpn-setup-nginx.sh" "$T/www"
check "off: nginx, поставленный нами, остановлен" grep -q "systemctl disable --now nginx" "$T/log"

# ---------------- живой nginx: TLS1.3 + h2 + сайт ----------------
if command -v nginx >/dev/null 2>&1 && openssl version >/dev/null 2>&1; then
  L="$T/live"; mkdir -p "$L/conf/sites-available" "$L/conf/sites-enabled" "$L/run"
  cat > "$L/nginx.conf" <<EOF
pid $L/run/nginx.pid; error_log $L/error.log; events {}
http { access_log off; client_body_temp_path $L/run; proxy_temp_path $L/run; fastcgi_temp_path $L/run; uwsgi_temp_path $L/run; scgi_temp_path $L/run;
  include /etc/nginx/mime.types; include $L/conf/sites-enabled/*; }
EOF
  PORT=$(DOMAIN_PORT="" mod domain_pick_port)
  # конфиг пишет модуль (nginx-заглушка для -t/reload), блок :80 убираем — тест не трогает системный nginx и порт 80
  # заглушка: версия — от настоящего nginx (выбор синтаксиса http2), -t/reload — ничего не делают
  mkdir -p "$T/nb2"; printf '#!/bin/sh\ncase "$1" in -v) exec %s -v;; esac\nexit 0\n' "$(command -v nginx)" > "$T/nb2/nginx"; chmod +x "$T/nb2/nginx"
  OUT=$(DOMAIN_NGINX_DIR="$L/conf" DOMAIN_CERT_MODE=selfsigned PATH="$T/nb2:$T/stub:$PATH" mod domain_write_nginx live.example "$PORT" full)
  python3 - "$L/conf/sites-available/vpn-setup-domain.conf" <<'PY'
import re,sys
p=sys.argv[1]; s=open(p).read()
s=re.sub(r"server \{\s*listen 80 default_server;.*?\n\}\n", "", s, flags=re.S)
open(p,"w").write(s)
PY
  DOMAIN_SELF_DIR="$T/self" DOMAIN_CERT_MODE=selfsigned mod domain_cert live.example >/dev/null
  mod domain_decoy live.example >/dev/null
  if nginx -c "$L/nginx.conf" -t -q 2>/dev/null && nginx -c "$L/nginx.conf" 2>/dev/null; then
    sleep 1
    OUT=$(mod domain_local_probe live.example "$PORT" && echo PROBE-OK); check "live: nginx отдаёт сайт по TLS1.3 + HTTP/2 на 127.0.0.1:$PORT" has "$OUT" PROBE-OK
    OUT=$(curl -sk --noproxy '*' --resolve "live.example:$PORT:127.0.0.1" "https://live.example:$PORT/nope" -w '%{http_code}' -o "$T/404.html"); check "live: 404 — своя страница" bash -c '[ "$1" = 404 ] && grep -q "404" "$2"' _ "$OUT" "$T/404.html"
    OUT=$(curl -sk --noproxy '*' --resolve "live.example:$PORT:127.0.0.1" "https://live.example:$PORT/work" -o /dev/null -w '%{http_code}'); check "live: /work без .html" [ "$OUT" = 200 ]
    OUT=$(curl -sk --noproxy '*' --resolve "live.example:$PORT:127.0.0.1" "https://live.example:$PORT/.vpn-setup-site" -o /dev/null -w '%{http_code}'); check "live: маркер /.vpn-setup-site скрыт (404)" [ "$OUT" = 404 ]
    OUT=$(ss -Htln "sport = :$PORT" | awk '{print $4}'); check "live: слушает только loopback" [ "$OUT" = "127.0.0.1:$PORT" ]
    nginx -c "$L/nginx.conf" -s stop 2>/dev/null
  else
    SKIP=$((SKIP+1)); echo "SKIP  live nginx не запустился: $(nginx -c "$L/nginx.conf" -t 2>&1 | tail -n2)"
  fi
else
  SKIP=$((SKIP+1)); echo "SKIP  live: nginx не установлен"
fi

echo; echo "== итог: PASS $PASS, FAIL $FAIL, SKIP $SKIP"
[ "$FAIL" = 0 ] || { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
