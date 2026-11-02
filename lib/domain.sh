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
    location ~ /\. { return 404; }
    location ^~ /data/ {
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Strict-Transport-Security "max-age=31536000" always;
        try_files \$uri =404;
    }
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

# ---------- сайт-заглушка (шаблоны lib/sites/<id>) ----------
# Шаблоны вшиты в install.sh при сборке (build.sh → base64 tar.gz). В исходниках (тесты) берутся из lib/sites.
DOMAIN_CRON_FILE=${DOMAIN_CRON_FILE:-/etc/cron.d/vpn-setup-site}
DOMAIN_SITE_MARK=.vpn-setup-site
DOMAIN_SITES_SRC=${DOMAIN_SITES_SRC:-}
_domain_sites_payload(){ cat <<'SITESEOF'
@@SITES@@
SITESEOF
}
_domain_sites_dir(){ # печатает каталог с распакованными шаблонами (render.py, card/, status/, rates/)
  local p dir here
  if [ -n "$DOMAIN_SITES_SRC" ] && [ -f "$DOMAIN_SITES_SRC/render.py" ]; then echo "$DOMAIN_SITES_SRC"; return 0; fi
  p=$(_domain_sites_payload)
  if [ ${#p} -lt 100 ]; then   # несобранный модуль: шаблоны рядом, в lib/sites
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    [ -f "$here/sites/render.py" ] || die "шаблоны сайтов не найдены ($here/sites)"
    echo "$here/sites"; return 0
  fi
  dir="$STATE/site/src"
  rm -rf "$dir"; install -d -m 700 "$dir"
  base64 -d <<<"$p" | tar -xzf - -C "$dir" || die "не удалось распаковать шаблоны сайтов"
  echo "$dir"
}
domain_site_list(){ # id|Название|описание
  echo "card|Визитка разработчика|страница фрилансера-веб-разработчика: работы, услуги, контакты"
  echo "status|Статус серверов|страница доступности с живыми данными этого сервера (аптайм, нагрузка, диск)"
  echo "rates|Курсы валют|курсы и конвертер валют, обновляются каждый час с открытого источника"
}
_domain_site_valid(){ domain_site_list | cut -d'|' -f1 | grep -qx -- "${1:-}"; }
_domain_site_hash(){ # хэш шаблона: при обновлении скрипта изменившийся шаблон пересобирается
  local src="$1" id="$2"
  (cd "$src" && find "$id" render.py -type f ! -name '*.pyc' -print0 | sort -z | xargs -0 cat) | sha256sum | cut -c1-16
}
_domain_site_cron(){ # _domain_site_cron ID ДОМЕН — периодическое обновление данных сайта (или удаление)
  local id="$1" d="$2" py dir="$DOMAIN_WWW_ROOT/$2/data" m
  py=$(command -v python3 || echo /usr/bin/python3)
  case "$id" in
    status) printf '# vpn-setup: данные страницы статуса %s\nSHELL=/bin/sh\n* * * * * root %s -I %s %s >/dev/null 2>&1\n' \
              "$d" "$py" "$STATE/site/collect.py" "$dir" > "$DOMAIN_CRON_FILE" ;;
    rates)  m=$(( $(printf '%s' "$d" | cksum | cut -d' ' -f1) % 50 + 5 ))
            printf '# vpn-setup: курсы валют для %s (раз в час)\nSHELL=/bin/sh\n%s * * * * root %s -I %s %s >/dev/null 2>&1\n' \
              "$d" "$m" "$py" "$STATE/site/fetch.py" "$dir" > "$DOMAIN_CRON_FILE" ;;
    *)      rm -f "$DOMAIN_CRON_FILE"; return 0 ;;
  esac
  chmod 644 "$DOMAIN_CRON_FILE"
}
domain_site_deploy(){ # domain_site_deploy ДОМЕН [ID] — сайт из шаблона; свой сайт пользователя не трогаем
  local d="$1" id="${2:-${SITE_TEMPLATE:-card}}" dir src hash old_id="" old_hash="" f list
  _domain_site_valid "$id" || die "нет такого шаблона сайта: $id (варианты: $(domain_site_list | cut -d'|' -f1 | tr '\n' ' '))"
  dir="$DOMAIN_WWW_ROOT/$d"
  if [ -f "$dir/$DOMAIN_SITE_MARK" ]; then
    read -r old_id old_hash < "$dir/$DOMAIN_SITE_MARK" || true
  elif [ -f "$dir/index.html" ]; then
    if grep -q 'written slowly, published rarely' "$dir/index.html" 2>/dev/null; then
      # заглушка прошлой версии vpn-setup — заменяем её файлы
      rm -f "$dir"/index.html "$dir"/about.html "$dir"/404.html "$dir"/style.css "$dir"/favicon.svg "$dir"/robots.txt "$dir"/sitemap.xml
      rm -rf "$dir/notes"
    else
      echo "сайт: в $dir уже есть свой index.html — не трогаю (шаблон «$id» не ставлю)"
      _domain_site_cron none "$d"
      return 0
    fi
  fi
  src=$(_domain_sites_dir)
  hash=$(_domain_site_hash "$src" "$id")
  if [ "$old_id" = "$id" ] && [ "$old_hash" = "$hash" ]; then
    echo "сайт: шаблон «$id» уже стоит"
  else
    if [ -n "$old_id" ]; then   # удаляем только файлы прошлого шаблона по манифесту; чужие файлы остаются
      list=$(tail -n +2 "$dir/$DOMAIN_SITE_MARK")
      while IFS= read -r f; do
        case "$f" in ""|*..*|/*) continue ;; esac
        rm -f "$dir/$f"
      done <<<"$list"
      rm -rf "$dir/data"
    fi
    install -d -m 755 "$dir"
    list=$(python3 -I "$src/render.py" "$id" "$src" "$dir" "$d") || die "не удалось собрать сайт из шаблона «$id»"
    { echo "$id $hash"; echo "$list"; } > "$dir/$DOMAIN_SITE_MARK"
    chmod 644 "$dir/$DOMAIN_SITE_MARK"
    echo "сайт: шаблон «$id» → $dir"
  fi
  install -d -m 700 "$STATE/site"
  case "$id" in
    status) install -m 600 "$src/status/collect.py" "$STATE/site/collect.py"
            python3 -I "$STATE/site/collect.py" "$dir/data" || warn "сбор данных для страницы статуса не удался" ;;
    rates)  install -m 600 "$src/rates/fetch.py" "$STATE/site/fetch.py"
            [ -s "$dir/data/rates.json" ] || python3 -I "$STATE/site/fetch.py" "$dir/data" \
              || warn "курсы пока не загрузились — сайт покажет «загружаются», cron повторит через час" ;;
  esac
  _domain_site_cron "$id" "$d"
  [ -d "$dir/data" ] && chmod 755 "$dir/data"
  chmod -R a+rX "$dir"
  return 0
}
domain_decoy(){ domain_site_deploy "$1" "${SITE_TEMPLATE:-card}"; }   # совместимость
cmd_site(){ # vpn-setup site [ID] — показать / сменить шаблон сайта-маски
  local id="${1:-}" cur line t desc
  require_installed; load_config
  cur=${SITE_TEMPLATE:-card}
  if [ -z "$id" ]; then
    echo "Шаблоны сайта-маски (используется в режиме своего домена):"
    while IFS='|' read -r line t desc; do
      if [ "$line" = "$cur" ]; then printf '  * %-7s %s — %s  (текущий)\n' "$line" "$t" "$desc"
      else printf '    %-7s %s — %s\n' "$line" "$t" "$desc"; fi
    done < <(domain_site_list)
    echo "Сменить: vpn-setup site ID     Свой сайт: положи файлы в /var/www/ДОМЕН (шаблон его не перезапишет)"
    [ -n "${DOMAIN:-}" ] || echo "Сейчас домен не подключён — шаблон будет использован после: vpn-setup domain ДОМЕН"
    return 0
  fi
  _domain_site_valid "$id" || die "нет такого шаблона: $id. Список: vpn-setup site"
  SITE_TEMPLATE="$id"
  if [ -n "${DOMAIN:-}" ]; then domain_site_deploy "$DOMAIN" "$id"; fi
  save_config
  echo "шаблон сайта: $id"
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
  domain_site_deploy "$d" "${SITE_TEMPLATE:-card}"
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
  rm -f "$DOMAIN_CRON_FILE"   # обновление данных сайта (статус/курсы) больше не нужно
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
