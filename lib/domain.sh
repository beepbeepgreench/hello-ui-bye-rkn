#!/usr/bin/env bash
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

# ---------- сайт-заглушка ----------
domain_decoy(){ # создаёт сайт в $DOMAIN_WWW_ROOT/ДОМЕН, если там ещё нет index.html (свой сайт не трогаем)
  local d="$1" dir title y
  dir="$DOMAIN_WWW_ROOT/$d"
  if [ -f "$dir/index.html" ]; then echo "сайт: $dir уже есть — не трогаю"; return 0; fi
  install -d -m 755 "$dir" "$dir/notes"
  title=$(python3 -I -c 'import sys; b=sys.argv[1].split(".")[0].encode().decode("idna") if sys.argv[1].startswith("xn--") else sys.argv[1].split(".")[0]; print(" ".join(w.capitalize() for w in b.replace("_","-").split("-")))' "$d" 2>/dev/null) || title="Field Notes"
  y=$(date +%Y)
  cat > "$dir/style.css" <<'EOF'
:root{--bg:#fbfaf7;--fg:#22211f;--mut:#6d6a63;--acc:#2f6f5e;--line:#e7e3da}
@media (prefers-color-scheme:dark){:root{--bg:#171715;--fg:#e9e6df;--mut:#a29e94;--acc:#7cc2ad;--line:#2c2b27}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.65 Georgia,"Times New Roman",serif}
.wrap{max-width:720px;margin:0 auto;padding:40px 20px 64px}
header{display:flex;justify-content:space-between;align-items:baseline;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:28px}
header a.brand{font-size:22px;font-weight:bold;color:var(--fg);text-decoration:none}
nav a{color:var(--mut);margin-left:16px;text-decoration:none;font-family:system-ui,sans-serif;font-size:15px}nav a:hover{color:var(--acc)}
h1,h2{line-height:1.25}a{color:var(--acc)}.meta{color:var(--mut);font:14px system-ui,sans-serif}
article{margin-bottom:34px}article h2{margin:0 0 4px;font-size:22px}article h2 a{color:var(--fg);text-decoration:none}
footer{border-top:1px solid var(--line);margin-top:40px;padding-top:14px;color:var(--mut);font:14px system-ui,sans-serif}
EOF
  cat > "$dir/favicon.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#2f6f5e"/><path d="M9 22c4-1 7-5 8-12 2 5 4 9 7 11" stroke="#fbfaf7" stroke-width="2.4" fill="none" stroke-linecap="round"/></svg>
EOF
  _domain_page(){ # _domain_page ФАЙЛ ЗАГОЛОВОК ТЕЛО
    cat > "$1" <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$2</title><meta name="description" content="Notes on film photography, long walks and small repairs.">
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/style.css"></head>
<body><div class="wrap">
<header><a class="brand" href="/">$title</a><nav><a href="/">Notes</a><a href="/about">About</a></nav></header>
$3
<footer>© $y $title · written slowly, published rarely</footer>
</div></body></html>
EOF
  }
  _domain_page "$dir/index.html" "$title — notes" '
<article><h2><a href="/notes/expired-film">Shooting expired film in winter</a></h2>
<p class="meta">January · 6 min read</p>
<p>Three rolls of Fomapan that expired in 2009, one cheap rangefinder and a week of grey skies. What came out, what did not, and why I now overexpose everything by two stops.</p></article>
<article><h2><a href="/notes/bike-wheel">Truing a bicycle wheel without a stand</a></h2>
<p class="meta">November · 4 min read</p>
<p>Zip ties, a spoke key and patience. A small guide for the kitchen-table mechanic.</p></article>
<article><h2><a href="/notes/river-walk">Forty kilometres along the river</a></h2>
<p class="meta">September · 8 min read</p>
<p>Two days, one tent, too many photos of bridges. A route that is flat, quiet and has a bakery at both ends.</p></article>'
  _domain_page "$dir/about.html" "About — $title" '
<h1>About</h1>
<p>Hi. This is a small personal notebook: film photography, walking routes, and fixing things instead of throwing them away.</p>
<p>No ads, no tracking, no newsletter. Posts appear when there is something worth writing down.</p>'
  _domain_page "$dir/notes/expired-film.html" "Shooting expired film in winter — $title" '
<h1>Shooting expired film in winter</h1><p class="meta">January · 6 min read</p>
<p>Old black-and-white film loses speed and gains fog. The usual rule is one stop of extra exposure per decade; with cold storage you can be gentler.</p>
<p>I metered for ISO 25 instead of 100, developed in Rodinal 1+50 for eleven minutes and got thin but printable negatives. Grain is heavy, contrast is soft, and the snow looks like old paper — which is exactly what I wanted.</p>'
  _domain_page "$dir/notes/bike-wheel.html" "Truing a bicycle wheel without a stand — $title" '
<h1>Truing a bicycle wheel without a stand</h1><p class="meta">November · 4 min read</p>
<p>Flip the bike, fix a zip tie to the frame so its tail almost touches the rim, and spin. Where the rim touches the tie, loosen the spoke on that side and tighten the opposite one by a quarter turn.</p>
<p>Small steps. Re-check often. Stop when it is good enough — perfect is for people with stands.</p>'
  _domain_page "$dir/notes/river-walk.html" "Forty kilometres along the river — $title" '
<h1>Forty kilometres along the river</h1><p class="meta">September · 8 min read</p>
<p>The path follows the old towpath almost the whole way. Water every ten kilometres, shade until noon, and a ferry that only runs on weekends — check before you go.</p>'
  _domain_page "$dir/404.html" "Not found — $title" '<h1>Not found</h1><p>This page does not exist (any more). Try the <a href="/">notes</a>.</p>'
  printf 'User-agent: *\nAllow: /\nSitemap: https://%s/sitemap.xml\n' "$d" > "$dir/robots.txt"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    for u in "" about notes/expired-film notes/bike-wheel notes/river-walk; do echo "  <url><loc>https://$d/$u</loc></url>"; done
    echo '</urlset>'
  } > "$dir/sitemap.xml"
  # «живые» даты изменения: страницы писались в прошлые месяцы, а не в момент установки
  local f i=0
  for f in "$dir"/notes/river-walk.html "$dir"/notes/bike-wheel.html "$dir"/about.html "$dir"/notes/expired-film.html \
           "$dir"/404.html "$dir"/style.css "$dir"/favicon.svg "$dir"/robots.txt "$dir"/sitemap.xml "$dir"/index.html; do
    i=$((i+1)); touch -d "@$(( $(date +%s) - (200 - i*17) * 86400 - RANDOM ))" "$f" 2>/dev/null || true
  done
  chmod -R a+rX "$dir"
  echo "сайт-заглушка: $dir (можно заменить своими файлами — vpn-setup его больше не перезапишет)"
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
  domain_decoy "$d"
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
