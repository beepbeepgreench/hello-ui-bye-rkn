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

# ---------------- сайт-заглушка ----------------
OUT=$(mod domain_decoy lenafoto.net)
check "decoy: создан index/about/notes/404/robots/sitemap/favicon" bash -c 'for f in index.html about.html notes/expired-film.html 404.html robots.txt sitemap.xml favicon.svg style.css; do [ -s "$1/$f" ] || exit 1; done' _ "$T/www/lenafoto.net"
check "decoy: не страница nginx по умолчанию, заголовок из имени" grep -q '<title>Lenafoto' "$T/www/lenafoto.net/index.html"
check "decoy: даты изменения в прошлом (>20 дней)" bash -c '[ $(( $(date +%s) - $(stat -c %Y "$1") )) -gt 1728000 ]' _ "$T/www/lenafoto.net/index.html"
check "decoy: в тексте нет слов vpn/proxy/xray" bash -c '! grep -rqiE "vpn|proxy|xray|reality" "$1"' _ "$T/www/lenafoto.net"
echo "my own site" > "$T/www/lenafoto.net/index.html"
OUT=$(mod domain_decoy lenafoto.net); check "decoy: свой сайт пользователя не перезаписывается" grep -qx "my own site" "$T/www/lenafoto.net/index.html"

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
    OUT=$(curl -sk --noproxy '*' --resolve "live.example:$PORT:127.0.0.1" "https://live.example:$PORT/nope" -w '%{http_code}' -o "$T/404.html"); check "live: 404 — своя страница" bash -c '[ "$1" = 404 ] && grep -q "Not found" "$2"' _ "$OUT" "$T/404.html"
    OUT=$(curl -sk --noproxy '*' --resolve "live.example:$PORT:127.0.0.1" "https://live.example:$PORT/about" -o /dev/null -w '%{http_code}'); check "live: /about без .html" [ "$OUT" = 200 ]
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
