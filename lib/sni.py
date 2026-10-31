#!/usr/bin/env python3
"""Подбор и проверка сайта маскировки (target/SNI) для Xray REALITY.

Только stdlib + `openssl` CLI (проверка X25519). Работает под `python3 -I`, Python 3.10+.

  sni.py check DOMAIN [--json]                    вердикт OK/WARN/FAIL (код 0/1/2)
  sni.py scan [--neighbors IP] [--limit N] [--json] рейтинг кандидатов (+ соседи по /24)
  sni.py pick [--neighbors IP] [--default DOMAIN] интерактивный выбор; домен — последней строкой stdout

Общие флаги (для тестов): --resolve DOMAIN:IP (можно несколько), --port N, --cafile PATH,
  --no-http, --timeout S, --candidates a,b,c (заменить встроенный список), --non-interactive.
"""
import argparse, ipaddress, json, os, queue, re, shutil, socket, ssl, subprocess, sys, tempfile, threading, time
from urllib.parse import urlsplit

OK, WARN, FAIL = 0, 1, 2
VNAME = {OK: "OK", WARN: "WARN", FAIL: "FAIL"}
LATENCY_WARN_MS = 150

# Скучные, посещаемые, неполитические сайты; страна — для подсказки. Всё проверяется на лету,
# CDN-фронтированные отсеются проверкой, так что список намеренно с запасом.
CANDIDATES = [
    ("www.lidl.de", "DE"), ("www.otto.de", "DE"), ("www.dhl.de", "DE"), ("www.rewe.de", "DE"),
    ("www.bahn.de", "DE"), ("www.kaufland.de", "DE"), ("www.dm.de", "DE"), ("www.hornbach.de", "DE"),
    ("www.ah.nl", "NL"), ("www.ns.nl", "NL"), ("www.postnl.nl", "NL"), ("www.jumbo.com", "NL"),
    ("www.s-kanava.fi", "FI"), ("www.k-ruoka.fi", "FI"), ("www.posti.fi", "FI"), ("www.vr.fi", "FI"),
    ("www.ica.se", "SE"), ("www.postnord.se", "SE"), ("www.sj.se", "SE"),
    ("www.inpost.pl", "PL"), ("www.intercity.pl", "PL"), ("www.pkobp.pl", "PL"), ("www.biedronka.pl", "PL"),
    ("www.carrefour.fr", "FR"), ("www.laposte.fr", "FR"), ("www.leroymerlin.fr", "FR"),
    ("www.billa.at", "AT"), ("www.oebb.at", "AT"), ("www.post.at", "AT"),
    ("www.alza.cz", "CZ"), ("www.cd.cz", "CZ"), ("www.seznam.cz", "CZ"),
    ("www.rimi.ee", "EE"), ("www.omniva.ee", "EE"),
    ("www.rimi.lv", "LV"), ("www.airbaltic.com", "LV"),
    ("www.maxima.lt", "LT"), ("www.post.lt", "LT"),
    ("www.esselunga.it", "IT"), ("www.poste.it", "IT"), ("www.trenitalia.com", "IT"),
    ("www.mercadona.es", "ES"), ("www.renfe.com", "ES"), ("www.correos.es", "ES"),
]

# Имена, которые используют все подряд: их SNI на чужом IP — заметный признак.
OVERUSED = ("microsoft", "apple", "icloud", "google", "gstatic", "youtube", "yahoo", "amazon", "aws",
            "cloudflare", "github", "speedtest", "bing", "live", "office", "azure", "samsung", "nvidia",
            "mozilla", "discord", "whatsapp", "telegram", "lovelive-anime", "dl", "swdist", "addons")

# Компактный список крупных CDN (IPv4). Остальное считаем «не CDN».
CDN_RANGES = {
    "Cloudflare": "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 "
                  "108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 "
                  "162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22",
    "Fastly": "23.235.32.0/20 43.249.72.0/22 103.244.50.0/24 103.245.222.0/23 103.245.224.0/24 "
              "104.156.80.0/20 140.248.64.0/18 140.248.128.0/17 146.75.0.0/17 151.101.0.0/16 "
              "157.52.64.0/18 167.82.0.0/17 167.82.128.0/20 167.82.160.0/20 167.82.224.0/20 "
              "172.111.64.0/18 185.31.16.0/22 199.27.72.0/21 199.232.0.0/16",
    "Akamai": "23.0.0.0/12 23.32.0.0/11 23.64.0.0/14 23.192.0.0/11 2.16.0.0/13 95.100.0.0/15 "
              "104.64.0.0/10 184.24.0.0/13 184.50.0.0/15 184.84.0.0/14 96.6.0.0/15 96.16.0.0/15 "
              "72.246.0.0/15 88.221.0.0/16 92.122.0.0/15 173.222.0.0/15",
    "CloudFront": "13.32.0.0/15 13.224.0.0/14 18.64.0.0/14 18.154.0.0/15 18.160.0.0/15 18.164.0.0/15 "
                  "18.172.0.0/15 52.84.0.0/15 54.182.0.0/16 54.192.0.0/16 54.230.0.0/16 54.239.128.0/18 "
                  "65.8.0.0/16 65.9.0.0/17 99.84.0.0/16 99.86.0.0/16 108.138.0.0/15 108.156.0.0/14 "
                  "143.204.0.0/16 205.251.192.0/19 216.137.32.0/19",
}
_CDN_NETS = [(name, ipaddress.ip_network(n)) for name, nets in CDN_RANGES.items() for n in nets.split()]
# Заголовки ответа, по которым CDN видно даже вне известных диапазонов.
CDN_HEADERS = [("server", r"cloudflare", "Cloudflare"), ("cf-ray", r".", "Cloudflare"),
               ("x-amz-cf-id", r".", "CloudFront"), ("via", r"cloudfront", "CloudFront"),
               ("x-served-by", r"cache-", "Fastly"), ("x-fastly-request-id", r".", "Fastly"),
               ("server", r"akamai", "Akamai")]
_2LD = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "gv"}
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")

OPT = argparse.Namespace(resolve={}, port=443, cafile=None, no_http=False, timeout=4.0)


def log(msg=""):
    print(msg, file=sys.stderr, flush=True)


def cdn_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((name for name, net in _CDN_NETS if a.version == net.version and a in net), None)


def registrable(host):
    lab = host.lower().rstrip(".").split(".")
    if len(lab) >= 3 and lab[-2] in _2LD and len(lab[-1]) == 2:
        return ".".join(lab[-3:])
    return ".".join(lab[-2:])


def overused(host):
    return next((t for t in OVERUSED for lab in host.lower().split(".")[:-1] if t == lab or
                 (len(t) > 4 and t in lab)), None)


def in_thread(fn, timeout):
    """Выполнить fn с жёстким таймаутом (getaddrinfo нельзя прервать иначе)."""
    box = {}

    def run():
        try:
            box["r"] = fn()
        except BaseException as e:  # noqa: BLE001 — передаём наружу
            box["e"] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if "e" in box:
        raise box["e"]
    if "r" not in box:
        raise TimeoutError("timeout")
    return box["r"]


def resolve4(host):
    if host in OPT.resolve:
        return [OPT.resolve[host]]
    infos = in_thread(lambda: socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM), OPT.timeout)
    out = []
    for i in infos:
        if i[4][0] not in out:
            out.append(i[4][0])
    return out


def tls_connect(ip, sni, alpn, verify, min13=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if min13:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if verify:
        ctx.check_hostname, ctx.verify_mode = True, ssl.CERT_REQUIRED
        if OPT.cafile:
            ctx.load_verify_locations(OPT.cafile)
        else:
            ctx.load_default_certs()
    else:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    raw = socket.create_connection((ip, OPT.port), timeout=OPT.timeout)
    try:
        t0 = time.monotonic()
        s = ctx.wrap_socket(raw, server_hostname=sni)
        return s, (time.monotonic() - t0) * 1000
    except BaseException:
        raw.close()
        raise


def net_reason(e):
    if isinstance(e, ConnectionRefusedError):
        return f"порт {OPT.port} закрыт (соединение отклонено)"
    if isinstance(e, (socket.timeout, TimeoutError)):
        return f"нет ответа на порт {OPT.port} (таймаут {OPT.timeout:g} с)"
    if isinstance(e, ssl.SSLCertVerificationError):
        m = e.verify_message or str(e)
        if "Hostname mismatch" in m or "IP address mismatch" in m:
            return "сертификат выдан на другое имя"
        if "expired" in m:
            return "сертификат просрочен"
        if "self-signed" in m or "self signed" in m:
            return "самоподписанный сертификат"
        if "issuer" in m:
            return "сертификат не подтверждается доверенными центрами (CA)"
        return f"сертификат не прошёл проверку: {m}"
    if isinstance(e, ssl.SSLError):
        s = str(e).upper()
        if "PROTOCOL_VERSION" in s or "UNSUPPORTED_PROTOCOL" in s or "WRONG_VERSION" in s or "NO_PROTOCOLS" in s:
            return "сервер не поддерживает TLS 1.3"
        return f"ошибка TLS: {e.reason or e}"
    if isinstance(e, OSError):
        return f"сетевая ошибка: {e.strerror or e}"
    return f"ошибка: {e}"


def check_x25519(ip, sni):
    """True/False — поддерживает ли X25519 в TLS 1.3; None — не удалось проверить."""
    exe = shutil.which("openssl")
    if not exe:
        return None
    try:
        p = subprocess.run([exe, "s_client", "-connect", f"{ip}:{OPT.port}", "-servername", sni,
                            "-tls1_3", "-groups", "X25519", "-alpn", "h2"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=OPT.timeout + 2)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = p.stdout + p.stderr
    # OpenSSL 1.1/3.0/3.1: "Server Temp Key: X25519"; 3.2+: "Peer Temp Key"/"Negotiated TLS1.3 group: X25519".
    # Группа задана единственной, так что её появление в выводе и есть ответ; код возврата не важен
    # (сервер мог просто закрыть соединение сразу после рукопожатия).
    return bool(re.search(r"(?:Temp Key|TLS1\.3 group):\s*X25519", out))


def http_get(ip, host):
    """GET / по HTTP/1.1 поверх TLS. Возвращает (status, headers{lower: value}).
    Без ALPN: часть серверов на ALPN «только http/1.1» отвечает фатальным no_application_protocol."""
    s, _ = tls_connect(ip, host, None, verify=False, min13=False)
    with s:
        s.settimeout(OPT.timeout)
        s.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
                   "Gecko/20100101 Firefox/128.0\r\nAccept: text/html,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n"
                   "Connection: close\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            try:
                chunk = s.recv(8192)
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    if not m:
        raise ValueError("не HTTP-ответ")
    hdr = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdr.setdefault(k.strip().lower(), v.strip())
    return int(m.group(1)), hdr


def check(domain):
    d = domain.strip().lower().rstrip(".")
    r = {"domain": d, "ip": None, "verdict": OK, "reasons": [], "latency_ms": None, "tls13": None,
         "alpn": None, "cert_ok": None, "x25519": None, "http_status": None, "cdn": None}

    def bad(level, msg):
        r["reasons"].append(msg)
        r["verdict"] = max(r["verdict"], level)

    def done():
        r["verdict_name"] = VNAME[r["verdict"]]
        return r

    if d.startswith(("http://", "https://")):
        d = urlsplit(d).hostname or ""
        r["domain"] = d
    if not HOST_RE.match(d):
        bad(FAIL, "некорректное доменное имя (нужно вида www.example.de, без IP и пути)")
        return done()
    try:
        ips = resolve4(d)
    except (OSError, TimeoutError):
        ips = []
    if not ips:
        bad(FAIL, "нет DNS A-записи (домен не резолвится в IPv4)")
        return done()
    ip = r["ip"] = ips[0]
    for a in ips:
        c = cdn_of(a)
        if c:
            r["cdn"] = c
            bad(FAIL, f"сайт за CDN {c} ({a}) — общий IP, маскировка под него плохая")
            return done()
    o = overused(d)
    if o:
        bad(WARN, f"слишком популярное для маскировки имя («{o}») — его используют многие VPN")

    # 1) честное рукопожатие: TLS 1.3 + h2 + проверка сертификата на это имя
    sock = None
    try:
        sock, hs = tls_connect(ip, d, ["h2"], verify=True)
        r["cert_ok"] = True
    except ssl.SSLCertVerificationError as e:
        r["cert_ok"] = False
        bad(FAIL, net_reason(e))
        try:  # узнать остальное без проверки сертификата
            sock, hs = tls_connect(ip, d, ["h2"], verify=False)
        except (OSError, ssl.SSLError) as e2:
            bad(FAIL, net_reason(e2))
            return done()
    except (OSError, ssl.SSLError) as e:
        if isinstance(e, ssl.SSLError) and "TLS 1.3" in net_reason(e):
            r["tls13"] = False
        bad(FAIL, net_reason(e))
        return done()
    with sock:
        r["tls13"] = sock.version() == "TLSv1.3"
        r["alpn"] = sock.selected_alpn_protocol()
    r["latency_ms"] = round(hs)
    if not r["tls13"]:
        bad(FAIL, "сервер не поддерживает TLS 1.3")
    if r["alpn"] != "h2":
        bad(FAIL, "нет HTTP/2 (ALPN h2) — Reality с таким сайтом заметен")
    if hs > LATENCY_WARN_MS:
        bad(WARN, f"далеко от сервера: рукопожатие {round(hs)} мс (> {LATENCY_WARN_MS} мс)")

    # 2) X25519
    x = r["x25519"] = check_x25519(ip, d)
    if x is False:
        bad(FAIL, "сервер не поддерживает обмен ключами X25519")
    elif x is None:
        bad(WARN, "не удалось проверить X25519 (нет openssl или таймаут)")

    # 3) HTTP: живой ответ без ухода на чужой сайт, без признаков CDN в заголовках
    if not OPT.no_http:
        try:
            st, hdr = http_get(ip, d)
            r["http_status"] = st
            for k, pat, name in CDN_HEADERS:
                if k in hdr and re.search(pat, hdr[k], re.I):
                    r["cdn"] = name
                    bad(FAIL, f"ответ идёт через CDN {name} (заголовок {k})")
                    break
            if 300 <= st < 400:
                loc = hdr.get("location", "")
                u = urlsplit(loc)
                host = (u.hostname or "").lower()
                if not host:
                    pass
                elif u.scheme == "http":
                    bad(WARN, f"HTTP {st}: редирект на незашифрованный http://{host}")
                elif registrable(host) != registrable(d):
                    bad(FAIL, f"HTTP {st}: редиректит на другой сайт ({host}) — выберите конечный адрес")
                elif host != d:
                    bad(WARN, f"HTTP {st}: редирект на {host} — лучше указать сразу {host}")
            elif not 200 <= st < 300:
                bad(WARN, f"главная страница отвечает HTTP {st} (ожидался 2xx/3xx)")
        except (OSError, ssl.SSLError, ValueError) as e:
            bad(WARN, f"не удалось получить главную страницу ({net_reason(e) if isinstance(e, OSError) else e})")
    return done()


def summary(r):
    if r["reasons"]:
        return r["reasons"][0] + (f" (+{len(r['reasons']) - 1})" if len(r["reasons"]) > 1 else "")
    parts = ["TLS1.3", "h2", "X25519"]
    if r.get("http_status"):
        parts.append(f"HTTP {r['http_status']}")
    return " ".join(parts)


def print_check(r, out=sys.stdout):
    lat = f", {r['latency_ms']} мс" if r["latency_ms"] is not None else ""
    print(f"{r['domain']}: {r['verdict_name']}  (IP {r['ip'] or '—'}{lat})", file=out)
    for m in r["reasons"] or ["все проверки пройдены: TLS 1.3, h2, X25519, сертификат, HTTP"]:
        print(f"  - {m}", file=out)


# ---------- сканирование ----------

def parallel(fn, items, workers, deadline):
    """Параллельно fn(item) на daemon-потоках с жёстким дедлайном. Возвращает {index: result}."""
    q, res, lock = queue.Queue(), {}, threading.Lock()
    for i, it in enumerate(items):
        q.put((i, it))

    def worker():
        while time.monotonic() < deadline:
            try:
                i, it = q.get_nowait()
            except queue.Empty:
                return
            try:
                v = fn(it)
            except Exception as e:  # noqa: BLE001
                v = e
            with lock:
                res[i] = v
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, min(workers, len(items))))]
    for t in ts:
        t.start()
    for t in ts:
        t.join(max(0.0, deadline - time.monotonic()))
    with lock:
        return dict(res)


def cert_names(der):
    """CN + SAN DNS-имена из DER без проверки (через openssl x509)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    exe = shutil.which("openssl")
    names = []
    if exe:
        try:
            p = subprocess.run([exe, "x509", "-noout", "-subject", "-ext", "subjectAltName", "-nameopt", "multiline"],
                               input=pem, capture_output=True, text=True, timeout=5)
            names += re.findall(r"commonName\s*=\s*(\S+)", p.stdout)
            names += re.findall(r"DNS:([^,\s]+)", p.stdout)
        except (subprocess.TimeoutExpired, OSError):
            pass
    else:  # запасной путь: внутренний декодер CPython
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
        try:
            c = ssl._ssl._test_decode_cert(f.name)  # type: ignore[attr-defined]
            names += [v for rdn in c.get("subject", ()) for k, v in rdn if k == "commonName"]
            names += [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
        except Exception:  # noqa: BLE001
            pass
        finally:
            os.unlink(f.name)
    out = []
    for n in names:
        n = n.lower().rstrip(".")
        if n.startswith("*."):
            continue  # wildcard в SNI не подставить
        if HOST_RE.match(n) and n not in out:
            out.append(n)
    return out


def probe_neighbor(ip):
    """TLS 1.3 + h2 без проверки сертификата → имена из сертификата (как RealiTLScanner)."""
    try:
        s, _ = tls_connect(ip, None, ["h2"], verify=False)
    except (OSError, ssl.SSLError, ValueError):
        return ip, []
    with s:
        if s.version() != "TLSv1.3" or s.selected_alpn_protocol() != "h2":
            return ip, []
        der = s.getpeercert(binary_form=True)
    return ip, (cert_names(der) if der else [])


def neighbor_hosts(server_ip):
    a = ipaddress.ip_address(server_ip)
    if a.version != 4:
        raise ValueError("нужен IPv4")
    if (a.is_private or a.is_reserved or a.is_link_local) and not a.is_loopback:
        raise ValueError(f"{server_ip} — не публичный адрес, соседей сканировать бессмысленно")
    net = ipaddress.ip_network(f"{server_ip}/24", strict=False)
    return [str(h) for h in net.hosts() if h != a]


def scan(neighbors=None, candidates=None, quiet=False):
    t_start = time.monotonic()
    say = (lambda *_: None) if quiet else log
    jobs = []  # (domain, source)
    if neighbors:
        try:
            hosts = neighbor_hosts(neighbors)
        except ValueError as e:
            say(f"соседи: пропускаю — {e}")
            hosts = []
        if hosts:
            say(f"сканирую соседей {neighbors}/24 на порту {OPT.port} ({len(hosts)} адресов, до 30 с)…")
            pr = parallel(probe_neighbor, hosts, 64, time.monotonic() + 30)
            found = 0
            for v in pr.values():
                if isinstance(v, tuple) and v[1]:
                    found += 1
                    for n in v[1][:4]:
                        if all(n != j[0] for j in jobs):
                            jobs.append((n, f"сосед {v[0]}"))
            say(f"соседи: TLS1.3+h2 отвечают {found}, имён для проверки {len(jobs)}")
    for d, cc in (candidates if candidates is not None else CANDIDATES):
        if all(d != j[0] for j in jobs):
            jobs.append((d, cc))
    say(f"проверяю {len(jobs)} сайтов (до 60 с)…")
    res = parallel(lambda j: check(j[0]), jobs, 16, time.monotonic() + 60)
    rows = []
    for i, (d, src) in enumerate(jobs):
        r = res.get(i)
        if not isinstance(r, dict):
            r = {"domain": d, "ip": None, "verdict": FAIL, "verdict_name": "FAIL", "latency_ms": None,
                 "reasons": ["проверка не уложилась во время" if r is None else f"ошибка проверки: {r}"]}
        r["source"] = src
        r["neighbor"] = src.startswith("сосед")
        rows.append(r)
    rows.sort(key=lambda r: (0 if r["neighbor"] and r["verdict"] == OK else 1, r["verdict"],
                             r["latency_ms"] if r["latency_ms"] is not None else 10 ** 6, r["domain"]))
    say(f"готово за {time.monotonic() - t_start:.0f} с")
    return rows


def print_table(rows, limit, out):
    shown = [r for r in rows if r["verdict"] != FAIL][:limit]
    failed = [r for r in rows if r["verdict"] == FAIL]
    if shown:
        w = max(len(r["domain"]) for r in shown)
        ws = max(6, max(len(r["source"]) for r in shown))
        print(f"  {'#':>2}  {'домен'.ljust(w)}  {'откуда'.ljust(ws)}  итог  {'мс':>4}  примечание", file=out)
        for i, r in enumerate(shown, 1):
            lat = str(r["latency_ms"]) if r["latency_ms"] is not None else "—"
            print(f"  {i:>2}  {r['domain'].ljust(w)}  {r['source'].ljust(ws)}  {r['verdict_name']:<4}  {lat:>4}  "
                  f"{summary(r)}", file=out)
    else:
        print("  подходящих сайтов не найдено", file=out)
    if failed:
        print(f"  отброшено {len(failed)}: " + ", ".join(f"{r['domain']} ({r['reasons'][0]})" for r in failed[:6])
              + (" …" if len(failed) > 6 else ""), file=out)
    return shown


# ---------- выбор ----------

def open_tty():
    """(чтение, запись) для /dev/tty или None. Раздельные дескрипторы: tty не seekable, "r+" падает."""
    try:
        tin = open("/dev/tty", "r", encoding="utf-8", errors="replace")
        tout = open("/dev/tty", "w", encoding="utf-8", errors="replace", buffering=1)
        return tin, tout
    except OSError:
        return None


def pick(args):
    tty = None if args.non_interactive else open_tty()
    tin, tty = tty if tty else (None, None)
    cur = None
    if args.default:
        cur = check(args.default)
    rows = scan(args.neighbors, args.cand, quiet=False)
    if cur:
        rows = [r for r in rows if r["domain"] != cur["domain"]]
        cur["source"], cur["neighbor"] = "текущий", False
    if tty is None:
        if cur and cur["verdict"] == OK:
            print(cur["domain"])
            return 0
        best = next((r for r in rows if r["verdict"] == OK), None)
        print_table(rows, args.limit, sys.stderr)
        if not best:
            log("нет ни одного сайта с итогом OK — укажите домен вручную (SNI=...)")
            return 2
        log(f"выбран автоматически: {best['domain']}")
        print(best["domain"])
        return 0

    def say(msg=""):
        tty.write(msg + "\n")
        tty.flush()

    def ask(q):
        tty.write(q)
        tty.flush()
        ln = tin.readline()
        if not ln:
            raise EOFError
        return ln.strip()

    if cur and cur["verdict"] == WARN:  # текущий с замечаниями — на общих основаниях
        rows = sorted(rows + [cur], key=lambda r: (0 if r["neighbor"] and r["verdict"] == OK else 1, r["verdict"],
                                                   r["latency_ms"] if r["latency_ms"] is not None else 10 ** 6))
    shown = print_table(([cur] if cur and cur["verdict"] == OK else []) + rows, args.limit, tty)
    if cur and cur["verdict"] == FAIL:
        say(f"текущий {cur['domain']} больше не подходит: {'; '.join(cur['reasons'])}")
    dflt = shown[0] if shown else None
    try:
        while True:
            hint = f"Enter = {dflt['domain']}" if dflt else "введите домен"
            a = ask(f"Номер из списка, свой домен или Enter [{hint}]: ")
            if not a:
                if not dflt:
                    say("список пуст — введите домен сайта")
                    continue
                r = dflt
            elif a.isdigit():
                n = int(a)
                if not 1 <= n <= len(shown):
                    say(f"нет номера {n}; допустимо 1–{len(shown)}")
                    continue
                r = shown[n - 1]
            else:
                say(f"проверяю {a}…")
                r = check(a)
                print_check(r, tty)
            if r["verdict"] == FAIL:
                say("этот сайт не подходит, выберите другой")
                continue
            if r["verdict"] == WARN:
                if ask(f"{r['domain']}: есть замечания ({'; '.join(r['reasons'])}). Использовать? [y/N]: ").lower() \
                        not in ("y", "yes", "д", "да"):
                    continue
            say(f"выбран: {r['domain']}")
            print(r["domain"])
            return 0
    except EOFError:
        say("\nввод прерван")
        return 2


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--resolve", action="append", default=[], metavar="DOMAIN:IP")
    common.add_argument("--port", type=int, default=443)
    common.add_argument("--cafile")
    common.add_argument("--no-http", action="store_true")
    common.add_argument("--timeout", type=float, default=4.0)
    common.add_argument("--json", action="store_true")
    common.add_argument("--candidates", help="через запятую, вместо встроенного списка")
    p = argparse.ArgumentParser(prog="sni.py", description="Подбор сайта маскировки для Xray REALITY")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", parents=[common])
    c.add_argument("domain")
    for name in ("scan", "pick"):
        s = sub.add_parser(name, parents=[common])
        s.add_argument("--neighbors", metavar="SERVER_IP")
        s.add_argument("--limit", type=int, default=15)
        if name == "pick":
            s.add_argument("--default")
            s.add_argument("--non-interactive", action="store_true")
    a = p.parse_args(argv)
    for item in a.resolve:
        dom, _, ip = item.rpartition(":")
        if not dom or not ip:
            p.error(f"--resolve ожидает DOMAIN:IP, получено {item!r}")
        OPT.resolve[dom.lower()] = ip
    OPT.port, OPT.cafile, OPT.no_http, OPT.timeout = a.port, a.cafile, a.no_http, a.timeout
    a.cand = None
    if a.candidates is not None:
        a.cand = [(d.strip().lower(), "свой список") for d in a.candidates.split(",") if d.strip()]

    if a.cmd == "check":
        r = check(a.domain)
        if a.json:
            print(json.dumps(r, ensure_ascii=False, indent=2))
        else:
            print_check(r)
        return r["verdict"]
    if a.cmd == "scan":
        rows = scan(a.neighbors, a.cand, quiet=a.json)
        if a.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        else:
            print_table(rows, a.limit, sys.stdout)
        return min((r["verdict"] for r in rows), default=FAIL)
    return pick(a)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\nпрервано")
        sys.exit(130)
