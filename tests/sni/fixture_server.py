#!/usr/bin/env python3
"""Тестовый TLS 1.3 сервер: ALPN h2/http1.1; на HTTP/1.1 отвечает заданным статусом и Location.

fixture_server.py ADDR PORT CERT KEY STATUS [LOCATION] [--delay S]
"""
import argparse, socket, ssl, threading, time

a = argparse.ArgumentParser()
a.add_argument("addr"); a.add_argument("port", type=int); a.add_argument("cert"); a.add_argument("key")
a.add_argument("status", type=int); a.add_argument("location", nargs="?", default="")
a.add_argument("--delay", type=float, default=0.0)
o = a.parse_args()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(o.cert, o.key)
ctx.set_alpn_protocols(["h2", "http/1.1"])


def handle(c):
    try:
        if o.delay:
            time.sleep(o.delay)
        s = ctx.wrap_socket(c, server_side=True)
        if s.selected_alpn_protocol() == "h2":
            s.close(); return
        s.settimeout(3)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
        loc = f"Location: {o.location}\r\n" if o.location else ""
        s.sendall(f"HTTP/1.1 {o.status} X\r\n{loc}Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
        s.close()
    except Exception:
        c.close()


srv = socket.create_server((o.addr, o.port))
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
