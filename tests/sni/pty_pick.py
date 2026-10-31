#!/usr/bin/env python3
"""Запускает `sni.py pick` в псевдотерминале и отвечает на вопросы по сценарию.

pty_pick.py STDOUT_FILE SCRIPT_JSON -- sni.py pick ...
SCRIPT_JSON: [[ожидаемый_фрагмент, ответ], ...]; печатает весь вывод терминала, код = код дочернего.
"""
import json, os, pty, select, sys, time

out_file, steps = sys.argv[1], json.loads(sys.argv[2])
cmd = sys.argv[sys.argv.index("--") + 1:]
pid, fd = pty.fork()
if pid == 0:
    f = os.open(out_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.dup2(f, 1)  # stdout отдельно, UI идёт в /dev/tty (= этот pty)
    os.execvp(cmd[0], cmd)

buf, pos = "", 0


def read_until(frag, timeout=90):
    global buf, pos
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        i = buf.find(frag, pos)
        if i >= 0:
            pos = i + len(frag)
            return True
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                d = os.read(fd, 4096)
            except OSError:
                return False
            if not d:
                return False
            buf += d.decode("utf-8", "replace")
    return False


ok = True
for frag, answer in steps:
    if not read_until(frag):
        print(f"[pty] не дождался: {frag!r}", file=sys.stderr)
        ok = False
        break
    os.write(fd, (answer + "\n").encode())
# дочитать остаток
end, st = time.monotonic() + 30, None
while time.monotonic() < end:
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        try:
            d = os.read(fd, 4096)
        except OSError:
            break
        if not d:
            break
        buf += d.decode("utf-8", "replace")
    else:
        w, s = os.waitpid(pid, os.WNOHANG)
        if w:
            st = s
            break
if st is None:
    _, st = os.waitpid(pid, 0)
print(buf)
code = os.waitstatus_to_exitcode(st)
sys.exit(code if ok else 99)
