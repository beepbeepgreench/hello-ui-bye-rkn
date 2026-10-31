#!/usr/bin/env bash
# vpn-setup — 3X-UI + Xray одной командой: Reality-XHTTP, VLESS-enc+Sudoku, XHTTP-enc
# Ubuntu 22.04 / 24.04 / 26.04, amd64/arm64, запуск от root.
# Повторный запуск безопасен: ключи, пароли и клиенты сохраняются, новые имена из USERS добавляются.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/<АККАУНТ>/vpn-setup/main/install.sh)
#   bash install.sh harden-ssh     # отключить вход по паролю (только после проверки входа по ключу)
#
# Переменные (необязательно, иначе спросит): USERS, SSH_PUBKEY, SNI, PORT_REALITY, PORT_SUDOKU, PORT_XHTTP
set -Eeuo pipefail

XUI_VERSION="v3.8.5"   # закреплено: проверено с Xray 26.9.9 (Reality-XHTTP, Sudoku, VLESS-enc)
declare -A XUI_SHA256=(
  [amd64]="6a85c110a04a727613c933c54ae602b8d37dab8876c6e20a6d46623010dd9d3c"
  [arm64]="2dd601a32426fb19b0eafdffaead374a9cdb66be4dfb39407f9f50fa4e7234e7"
)
STATE=/root/vpn-setup
SNI_CANDIDATES="www.lidl.de www.otto.de www.dhl.de www.rewe.de www.bahn.de www.zalando.de"
PORT_REALITY=${PORT_REALITY:-443}
PORT_SUDOKU=${PORT_SUDOKU:-8443}
PORT_XHTTP=${PORT_XHTTP:-8080}

c_ok='\033[1;32m'; c_err='\033[1;31m'; c_warn='\033[1;33m'; c_no='\033[0m'
step(){ echo -e "\n${c_ok}==> $*${c_no}"; }
warn(){ echo -e "${c_warn}! $*${c_no}"; }
die(){ echo -e "\n${c_err}ОШИБКА: $*${c_no}" >&2; exit 1; }
trap 'die "строка $LINENO: команда завершилась с ошибкой: $BASH_COMMAND"' ERR
ask(){ # ask VAR "вопрос" "по умолчанию"
  local __v="$1" __q="$2" __d="${3:-}" __a=""
  if [ -n "${!__v:-}" ]; then return; fi
  if (: </dev/tty) 2>/dev/null; then read -r -p "$__q${__d:+ [$__d]}: " __a </dev/tty || true; fi
  printf -v "$__v" '%s' "${__a:-$__d}"
}

# ---------- отдельная команда: закрыть вход по паролю ----------
harden_ssh(){
  [ -s /root/.ssh/authorized_keys ] || die "в /root/.ssh/authorized_keys нет ключей"
  if ! journalctl -u ssh -u sshd --since "-24h" --no-pager 2>/dev/null | grep -c 'Accepted publickey for root' >/dev/null; then
    die "за последние 24 ч не было ни одного входа по ключу (Accepted publickey). Войди по ключу в новой сессии и повтори."
  fi
  cat > /etc/ssh/sshd_config.d/00-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 30
EOF
  install -d -m 755 /run/sshd
  sshd -t || { rm -f /etc/ssh/sshd_config.d/00-hardening.conf; die "sshd -t не прошёл, изменения отменены"; }
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
  sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin) ' || true
  echo -e "${c_ok}Готово. НЕ закрывай эту сессию, пока не проверишь вход по ключу в новой.${c_no}"
  echo "Откат: rm /etc/ssh/sshd_config.d/00-hardening.conf && systemctl restart ssh"
}
if [ "${1:-}" = "harden-ssh" ]; then [ "$(id -u)" = 0 ] || die "нужен root"; harden_ssh; exit 0; fi

# ---------- 0. проверки ----------
step "0/9 Проверки"
[ "$(id -u)" = 0 ] || die "запусти от root"
. /etc/os-release
[ "${ID:-}" = ubuntu ] || die "поддерживается только Ubuntu (обнаружено: ${PRETTY_NAME:-?})"
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; *) die "архитектура $(uname -m) не поддерживается";; esac
if systemctl list-unit-files x-ui.service >/dev/null 2>&1 && [ -f /etc/x-ui/x-ui.db ] && [ ! -f "$STATE/panel.env" ]; then
  die "здесь уже стоит 3X-UI, установленный не этим скриптом. Чтобы не сломать его, скрипт остановлен.
  Чистый сервер — лучший вариант. Если панель не нужна: 'x-ui uninstall', затем запусти скрипт снова."
fi
install -d -m 700 "$STATE"
install -d -m 755 /run/sshd   # Ubuntu 24.04+: без него 'sshd -T' падает, пока к SSH никто не подключался
SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}') || true
[ -n "$SSH_PORT" ] || SSH_PORT=$(grep -hE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2; exit}') || true
SSH_PORT=${SSH_PORT:-22}
for p in "$PORT_REALITY" "$PORT_SUDOKU" "$PORT_XHTTP"; do
  if ss -Htlnp "sport = :$p" | grep -v -e xray -e '^$' | grep -c . >/dev/null; then die "порт $p занят: $(ss -Htlnp "sport = :$p")"; fi
done
echo "Ubuntu ${VERSION_ID}, ${ARCH}, SSH на порту ${SSH_PORT}"

ask USERS "Имена пользователей латиницей через пробел" "$( [ -f "$STATE/users" ] && cat "$STATE/users" || echo HOME_PC)"
for u in $USERS; do [[ "$u" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die "имя '$u': только латиница, цифры, _ и -"; done
echo "$USERS" > "$STATE/users"
if [ ! -s /root/.ssh/authorized_keys ]; then
  ask SSH_PUBKEY "Публичный SSH-ключ (строка ssh-ed25519 AAAA… из MobaKeyGen, Enter — пропустить)" ""
fi

# ---------- 1. система ----------
step "1/9 Обновление системы и пакеты"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade
apt-get -y -q install curl ca-certificates openssl python3 ufw fail2ban qrencode sqlite3 tar >/dev/null
echo "пакеты установлены"

# ---------- 2. SSH ----------
step "2/9 SSH-ключ"
if [ -n "${SSH_PUBKEY:-}" ]; then
  case "$SSH_PUBKEY" in
    "ssh-ed25519 ssh-ed25519 "*) die "в ключе дважды 'ssh-ed25519' — вставь строку из MobaKeyGen целиком, ничего не дописывая";;
    ssh-ed25519\ AAAA*|ssh-rsa\ AAAA*|ecdsa-sha2-*\ AAAA*) ;;
    *) die "это не похоже на публичный ключ OpenSSH (должно начинаться с 'ssh-ed25519 AAAA')";;
  esac
  install -d -m 700 /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
  grep -qxF "$SSH_PUBKEY" /root/.ssh/authorized_keys || echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
  echo "ключ добавлен"
else
  echo "ключ не передан — пропускаю"
fi

# ---------- 3. ядро и сеть ----------
step "3/9 IPv6 off, BBR, swap"
IFACE=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
cat > /etc/sysctl.d/90-vpn.conf <<EOF
# vpn-setup: IPv6 выключен (у пользователей только IPv4), BBR для длинных каналов с потерями
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.${IFACE}.disable_ipv6 = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
vm.swappiness = 10
EOF
echo tcp_bbr > /etc/modules-load.d/bbr.conf
modprobe tcp_bbr 2>/dev/null || true
sysctl -q -p /etc/sysctl.d/90-vpn.conf
if [ -z "$(swapon --show --noheadings)" ] && [ "$(awk '/MemTotal/{print $2}' /proc/meminfo)" -lt 3000000 ]; then
  fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap -q /swapfile && swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "swap 1G создан"
fi
echo "интерфейс ${IFACE}: IPv6 off, $(sysctl -n net.ipv4.tcp_congestion_control)"

# ---------- 4. 3X-UI ----------
step "4/9 3X-UI ${XUI_VERSION}"
if [ ! -x /usr/local/x-ui/x-ui ] || ! /usr/local/x-ui/x-ui -v 2>/dev/null | grep -c "${XUI_VERSION#v}" >/dev/null; then
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  URL="https://github.com/MHSanaei/3x-ui/releases/download/${XUI_VERSION}/x-ui-linux-${ARCH}.tar.gz"
  curl -fsSL --retry 3 --connect-timeout 15 -o "$TMP/x-ui.tgz" "$URL"
  echo "${XUI_SHA256[$ARCH]}  $TMP/x-ui.tgz" | sha256sum -c --quiet - || die "контрольная сумма архива не совпала — установка остановлена"
  echo "контрольная сумма совпала"
  systemctl stop x-ui 2>/dev/null || true
  tar xzf "$TMP/x-ui.tgz" -C "$TMP"
  rm -rf /usr/local/x-ui && mv "$TMP/x-ui" /usr/local/x-ui
  chmod +x /usr/local/x-ui/x-ui /usr/local/x-ui/bin/xray-linux-"$ARCH" /usr/local/x-ui/x-ui.sh
  install -m 755 /usr/local/x-ui/x-ui.sh /usr/bin/x-ui
  install -m 644 /usr/local/x-ui/x-ui.service.debian /etc/systemd/system/x-ui.service
  install -d /var/log/x-ui
  systemctl daemon-reload
fi
XRAY_BIN=/usr/local/x-ui/bin/xray-linux-${ARCH}
"$XRAY_BIN" version 2>/dev/null | sed -n 1p

if [ ! -f "$STATE/panel.env" ]; then
  P_USER="u$(openssl rand -hex 5)"; P_PASS="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"
  P_PORT=$(( 20000 + $(od -An -N2 -tu2 /dev/urandom) % 40000 )); P_PATH="$(openssl rand -hex 8)"
  /usr/local/x-ui/x-ui setting -username "$P_USER" -password "$P_PASS" -port "$P_PORT" -webBasePath "$P_PATH" -listenIP 127.0.0.1 >/dev/null
  /usr/local/x-ui/x-ui migrate >/dev/null 2>&1 || true
  ( umask 077; printf 'P_USER=%q\nP_PASS=%q\nP_PORT=%q\nP_PATH=%q\n' "$P_USER" "$P_PASS" "$P_PORT" "$P_PATH" > "$STATE/panel.env" )
fi
# shellcheck disable=SC1091
. "$STATE/panel.env"
/usr/local/x-ui/x-ui setting -listenIP 127.0.0.1 >/dev/null
( umask 077; /usr/local/x-ui/x-ui setting -getApiToken -tokenName vpn-setup 2>/dev/null | awk '/apiToken:/{print $2}' > "$STATE/api.token" )
[ -s "$STATE/api.token" ] || die "не удалось получить API-токен панели"
systemctl enable --now x-ui >/dev/null 2>&1
systemctl restart x-ui
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null -H "Authorization: Bearer $(cat "$STATE/api.token")" "http://127.0.0.1:${P_PORT}/${P_PATH}/panel/api/inbounds/list" 2>/dev/null && break
  sleep 1
done
curl -fsS -o /dev/null -H "Authorization: Bearer $(cat "$STATE/api.token")" "http://127.0.0.1:${P_PORT}/${P_PATH}/panel/api/inbounds/list" \
  || { journalctl -u x-ui -n 20 --no-pager; die "панель не отвечает"; }
echo "панель запущена на 127.0.0.1:${P_PORT} (снаружи недоступна)"

# ---------- 5. маскировка Reality ----------
step "5/9 Сайт для маскировки Reality"
is_cf(){ [[ "$1" =~ ^(104\.(1[6-9]|2[0-9]|3[01])|172\.(6[4-9]|7[01])|188\.114|162\.158|173\.245|141\.101|131\.0\.7[2-5])\. ]]; }
sni_ok(){ local d="$1" o ip
  o=$(timeout 8 openssl s_client -connect "$d:443" -servername "$d" -tls1_3 -alpn h2 </dev/null 2>/dev/null) || true
  grep -q 'ALPN protocol: h2' <<<"$o" && grep -q 'Verify return code: 0 (ok)' <<<"$o" || return 1
  ip=$(getent ahostsv4 "$d" | awk 'NR==1{print $1}'); [ -n "$ip" ] && ! is_cf "$ip"; }
[ -z "${SNI:-}" ] && [ -s "$STATE/sni" ] && SNI=$(cat "$STATE/sni")
if [ -z "${SNI:-}" ]; then
  for d in $SNI_CANDIDATES; do if sni_ok "$d"; then SNI=$d; break; fi; done
fi
[ -n "${SNI:-}" ] || die "не нашёл подходящий сайт — задай вручную: SNI=www.example.de bash install.sh"
sni_ok "$SNI" || warn "$SNI сейчас не проходит проверку TLS1.3+h2 — Reality может работать нестабильно"
echo "$SNI" > "$STATE/sni"; echo "SNI: $SNI"

# ---------- 6. firewall + fail2ban ----------
step "6/9 Firewall и fail2ban"
sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw
ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null; ufw default deny routed >/dev/null
ufw allow "${SSH_PORT}/tcp" comment ssh >/dev/null
ufw allow "${PORT_REALITY}/tcp" comment 'xray reality-xhttp' >/dev/null
ufw allow "${PORT_SUDOKU}/tcp" comment 'xray sudoku' >/dev/null
ufw allow "${PORT_XHTTP}/tcp" comment 'xray xhttp' >/dev/null
ufw --force enable >/dev/null
ufw status | sed -n '1,12p'
cat > /etc/fail2ban/jail.d/sshd-vpn-setup.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
bantime = 1h
EOF
systemctl enable fail2ban >/dev/null 2>&1; systemctl restart fail2ban; sleep 3
fail2ban-client status sshd >/dev/null 2>&1 && echo "fail2ban: jail sshd активен" || warn "fail2ban не поднялся: journalctl -u fail2ban -n 20"

# ---------- 7. inbound'ы и клиенты ----------
step "7/9 Inbound'ы и пользователи"
PUBLIC_IP=${PUBLIC_IP:-$(curl -4 -fsS --max-time 10 https://ifconfig.co 2>/dev/null || curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)}
[[ "$PUBLIC_IP" =~ ^[0-9.]+$ ]] || PUBLIC_IP=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
[[ "$PUBLIC_IP" =~ ^[0-9.]+$ ]] || die "не удалось определить внешний IPv4"
install -d -m 700 "$STATE/keys"
cat > "$STATE/provision.py" <<'PYEOF'
#!/usr/bin/env python3
"""Create/refresh 3X-UI inbounds and clients through the panel API.

Idempotent: inbounds are found by tag, clients by email. Secrets live in STATE_DIR.
Env: PANEL_URL TOKEN_FILE STATE_DIR XRAY_BIN PUBLIC_IP USERS SNI
     PORT_REALITY PORT_SUDOKU PORT_XHTTP
"""
import json, os, re, secrets, subprocess, sys, urllib.request, urllib.error, urllib.parse, pathlib

E = os.environ
URL = E["PANEL_URL"].rstrip("/")
TOKEN = pathlib.Path(E["TOKEN_FILE"]).read_text().strip()
STATE = pathlib.Path(E["STATE_DIR"])
XRAY = E["XRAY_BIN"]
IP = E["PUBLIC_IP"]
USERS = E["USERS"].split()
SNI = E["SNI"]
P_REALITY, P_SUDOKU, P_XHTTP = int(E["PORT_REALITY"]), int(E["PORT_SUDOKU"]), int(E["PORT_XHTTP"])


def die(msg):
    print(f"ОШИБКА: {msg}", file=sys.stderr)
    sys.exit(1)


def api(method, path, body=None, quiet=False):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(URL + path, data=data, method=method, headers={
        "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        if quiet: raise SystemExit(1)
        die(f"{method} {path}: HTTP {e.code}")
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        if quiet: raise SystemExit(1)
        die(f"{method} {path}: панель недоступна ({e})")
    if not res.get("success", False):
        die(f"{method} {path}: {res.get('msg')}")
    return res.get("obj")


def secret(name, gen):
    f = STATE / name
    if not f.exists() or not f.read_text().strip():
        f.write_text(gen() + "\n")
        f.chmod(0o600)
    return f.read_text().strip()


def xray(*args):
    return subprocess.run([XRAY, *args], check=True, capture_output=True, text=True).stdout


def gen_x25519():
    out = xray("x25519")
    priv = re.search(r"PrivateKey:\s*(\S+)", out).group(1)
    pub = re.search(r"(?:PublicKey|Password)[^:]*:\s*(\S+)", out).group(1)
    return json.dumps({"private": priv, "public": pub})


def gen_vlessenc():
    out = xray("vlessenc")
    block = out.split("ML-KEM-768")[-1]  # post-quantum authentication pair
    dec = re.search(r'"decryption":\s*"([^"]+)"', block).group(1)
    enc = re.search(r'"encryption":\s*"([^"]+)"', block).group(1)
    return json.dumps({"decryption": dec, "encryption": enc})


STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
reality = json.loads(secret("reality.json", gen_x25519))
venc = json.loads(secret("vlessenc.json", gen_vlessenc))
sid = secret("reality.sid", lambda: secrets.token_hex(8))
p_reality = secret("path.reality", lambda: "/" + secrets.token_hex(6))
p_xhttp = secret("path.xhttp", lambda: "/" + secrets.token_hex(6))
sudoku_pw = secret("sudoku.pass", lambda: secrets.token_hex(32))

SNIFF = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": True})
XHTTP_BASE = {"mode": "auto", "host": "", "headers": {}, "noSSEHeader": False, "xPaddingBytes": "100-1000",
              "scMaxEachPostBytes": "1000000", "scMaxBufferedPosts": 30, "scStreamUpServerSecs": "20-80"}

INBOUNDS = [
    {"tag": "vpn-reality", "remark": "Reality-XHTTP", "port": P_REALITY,
     "settings": {"clients": [], "decryption": "none", "fallbacks": []},
     "stream": {"network": "xhttp", "security": "reality",
                "xhttpSettings": dict(XHTTP_BASE, path=p_reality),
                "realitySettings": {"show": False, "xver": 0, "target": f"{SNI}:443", "serverNames": [SNI],
                                    "privateKey": reality["private"], "shortIds": [sid],
                                    "minClientVer": "", "maxClientVer": "", "maxTimediff": 0,
                                    "settings": {"publicKey": reality["public"], "fingerprint": "firefox",
                                                 "serverName": "", "spiderX": "/"}}}},
    {"tag": "vpn-sudoku", "remark": "Sudoku-VLESSenc", "port": P_SUDOKU,
     "settings": {"clients": [], "decryption": venc["decryption"], "encryption": venc["encryption"]},
     "stream": {"network": "tcp", "security": "none",
                "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
                "finalmask": {"tcp": [{"type": "sudoku", "settings": {
                    "password": sudoku_pw, "ascii": "", "customTable": "", "customTables": [],
                    "paddingMin": 0, "paddingMax": 0}}]}}},
    {"tag": "vpn-xhttp", "remark": "XHTTP-VLESSenc", "port": P_XHTTP,
     "settings": {"clients": [], "decryption": venc["decryption"], "encryption": venc["encryption"]},
     "stream": {"network": "xhttp", "security": "none", "xhttpSettings": dict(XHTTP_BASE, path=p_xhttp)}},
]

# Subscription server: off and bound to localhost (phones reject its IP-only TLS anyway).
import time
st = api("POST", "/panel/api/setting/all")
if st.get("subEnable") or st.get("subListen") != "127.0.0.1":
    st["subEnable"], st["subListen"] = False, "127.0.0.1"
    api("POST", "/panel/api/setting/update", st)
    api("POST", "/panel/api/setting/restartPanel")
    for _ in range(30):
        time.sleep(1)
        try:
            api("GET", "/panel/api/inbounds/list", quiet=True); break
        except SystemExit:
            continue
    print("подписка: выключена (только localhost)")

existing = {ib["tag"]: ib for ib in (api("GET", "/panel/api/inbounds/list") or [])}
ids = []
for d in INBOUNDS:
    if d["tag"] in existing:
        ids.append(existing[d["tag"]]["id"])
        print(f"inbound {d['tag']}: уже есть (id {ids[-1]})")
        continue
    body = {"remark": d["remark"], "enable": True, "expiryTime": 0, "listen": "", "port": d["port"],
            "protocol": "vless", "tag": d["tag"], "settings": json.dumps(d["settings"]),
            "streamSettings": json.dumps(d["stream"]), "sniffing": SNIFF,
            "shareAddrStrategy": "custom", "shareAddr": IP, "trafficReset": "never"}
    obj = api("POST", "/panel/api/inbounds/add", body)
    ids.append(obj["id"])
    print(f"inbound {d['tag']}: создан (id {obj['id']}, порт {d['port']})")

have = {c.get("email") for c in (api("GET", "/panel/api/clients/list") or [])}
for u in USERS:
    if u in have:
        api("POST", f"/panel/api/clients/{urllib.parse.quote(u)}/attach", {"inboundIds": ids})
        print(f"клиент {u}: уже есть, привязан ко всем inbound")
        continue
    client = {"id": xray("uuid").strip(), "email": u, "flow": "", "enable": True, "limitIp": 0, "totalGB": 0,
              "expiryTime": 0, "tgId": 0, "subId": secrets.token_hex(8), "comment": "", "reset": 0}
    api("POST", "/panel/api/clients/add", {"client": client, "inboundIds": ids})
    print(f"клиент {u}: создан")

# Apply now and prove Xray accepted it: one bad inbound stops the whole core.
api("POST", "/panel/api/server/restartXrayService")
time.sleep(4)
cfg = os.path.join(os.path.dirname(XRAY), "config.json")
t = subprocess.run([XRAY, "run", "-test", "-c", cfg], capture_output=True, text=True)
if t.returncode != 0:
    for i in ids:
        api("POST", f"/panel/api/inbounds/setEnable/{i}", {"enable": False})
    api("POST", "/panel/api/server/restartXrayService")
    die("Xray не принял конфиг, новые inbound выключены, Xray перезапущен без них:\n"
        + (t.stdout + t.stderr).strip().splitlines()[-1])
print("Xray: конфиг принят")

out = []
for u in USERS:
    links = api("GET", f"/panel/api/clients/links/{urllib.parse.quote(u)}") or []
    out.append(f"### {u}")
    out.extend(links)
    out.append("")
(STATE / "links.txt").write_text("\n".join(out))
(STATE / "links.txt").chmod(0o600)
print(f"ссылки: {STATE / 'links.txt'}")
PYEOF
PANEL_URL="http://127.0.0.1:${P_PORT}/${P_PATH}" TOKEN_FILE="$STATE/api.token" STATE_DIR="$STATE/keys" \
XRAY_BIN="$XRAY_BIN" PUBLIC_IP="$PUBLIC_IP" USERS="$USERS" SNI="$SNI" \
PORT_REALITY="$PORT_REALITY" PORT_SUDOKU="$PORT_SUDOKU" PORT_XHTTP="$PORT_XHTTP" \
  python3 -I "$STATE/provision.py"

# ---------- 8. QR и бэкап ----------
step "8/9 QR-коды и бэкап"
install -d -m 700 "$STATE/qr"; rm -f "$STATE/qr/"*.png
cp "$STATE/keys/links.txt" "$STATE/links.txt"; chmod 600 "$STATE/links.txt"
while IFS= read -r l; do
  case "$l" in vless://*) n="${l##*#}"; n="${n//[^A-Za-z0-9_-]/_}"; qrencode -o "$STATE/qr/$n.png" "$l";; esac
done < "$STATE/links.txt"
install -d -m 700 "$STATE/backup"
sqlite3 /etc/x-ui/x-ui.db ".backup '$STATE/backup/x-ui-$(date +%F-%H%M).db'"
chmod 600 "$STATE/backup/"*
echo "QR: $(find "$STATE/qr" -name '*.png' | wc -l) шт., бэкап базы: $STATE/backup/"

# ---------- 9. проверка ----------
step "9/9 Проверка"
fail=0
for p in "$PORT_REALITY" "$PORT_SUDOKU" "$PORT_XHTTP"; do
  if ss -Htln "sport = :$p" | grep -c . >/dev/null; then echo "порт $p: слушается"; else echo "порт $p: НЕ слушается"; fail=1; fi
done
if ss -Htln "sport = :2096" | grep -c -e '0.0.0.0' -e '\*:' -e '\[::\]' >/dev/null; then warn "подписка 2096 слушает наружу"; fail=1; else echo "подписка: закрыта"; fi
if [ "$(ss -Htln "sport = :${P_PORT}" | grep -vc '127.0.0.1')" = 0 ] && ss -Htln "sport = :${P_PORT}" | grep -c . >/dev/null; then echo "панель: только 127.0.0.1"; else warn "панель: не только localhost или не слушает"; fail=1; fi
systemctl is-active --quiet x-ui && echo "x-ui: active" || fail=1

cat > "$STATE/README.txt" <<EOF
Сервер: ${PUBLIC_IP}    SNI Reality: ${SNI}    3X-UI: ${XUI_VERSION}
Профили:  Reality-XHTTP :${PORT_REALITY}  |  Sudoku-VLESSenc :${PORT_SUDOKU}  |  XHTTP-VLESSenc :${PORT_XHTTP}

Панель (только через SSH-туннель):
  MobaXterm → Tunneling → Local port forwarding: ${P_PORT} → 127.0.0.1:${P_PORT} через ${PUBLIC_IP}:${SSH_PORT}
  Браузер: http://127.0.0.1:${P_PORT}/${P_PATH}/
  Логин: ${P_USER}   Пароль: ${P_PASS}

Ссылки: ${STATE}/links.txt     QR: ${STATE}/qr/     Ключи: ${STATE}/keys/     Бэкапы: ${STATE}/backup/
Добавить людей:  USERS="старые имена + новые" bash install.sh   (старые ссылки не меняются)
Закрыть пароли SSH (после входа по ключу):  bash install.sh harden-ssh
EOF
chmod 600 "$STATE/README.txt"

echo
if [ "$fail" = 0 ]; then echo -e "${c_ok}ГОТОВО.${c_no}"; else echo -e "${c_warn}ГОТОВО С ЗАМЕЧАНИЯМИ — см. выше.${c_no}"; fi
echo "Всё про сервер (логин панели, туннель, файлы): cat $STATE/README.txt"
echo "Скачай через SFTP MobaXterm папку $STATE/qr и файл $STATE/links.txt — это секреты, не пересылай в открытые чаты."
if ! [ -f /etc/ssh/sshd_config.d/00-hardening.conf ]; then
  warn "Вход по паролю ещё включён. Проверь вход по ключу в НОВОЙ сессии, затем: bash install.sh harden-ssh"
fi
