#!/usr/bin/env python3
"""pty_drive.py TIMEOUT OUTFILE -- CMD... ; stdin-скрипт: строки «РЕГЭКСП<TAB>ОТВЕТ» (ответ с \\n в конце).
Запускает CMD в псевдотерминале, ждёт каждый регэксп в выводе и отправляет ответ. Весь вывод — в OUTFILE.
Код выхода: код CMD; 124 — тайм-аут; 125 — не дождались регэкспа."""
import os, pty, re, select, sys, time

timeout = float(sys.argv[1]); outfile = sys.argv[2]
cmd = sys.argv[sys.argv.index("--") + 1:]
script = []
for line in sys.stdin.read().splitlines():
    if not line.strip():
        continue
    rx, _, ans = line.partition("\t")
    script.append((re.compile(rx), ans.encode().decode("unicode_escape").encode("latin-1").decode("utf-8")))

pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)

buf = b""; pos = 0; step = 0; deadline = time.time() + timeout; rc = None
ansi = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
while True:
    if time.time() > deadline:
        os.kill(pid, 9); rc = 124; break
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
        if not data:
            break
        buf += data
    if step < len(script):
        text = ansi.sub(b"", buf[pos:]).decode("utf-8", "replace")
        m = script[step][0].search(text)
        if m:
            pos = len(buf)
            os.write(fd, script[step][1].encode())
            step += 1
if rc is None:
    _, st = os.waitpid(pid, 0)
    rc = os.waitstatus_to_exitcode(st)
    if step < len(script):
        rc = 125
open(outfile, "wb").write(ansi.sub(b"", buf))
sys.exit(rc)
