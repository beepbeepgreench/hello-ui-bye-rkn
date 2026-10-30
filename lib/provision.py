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
