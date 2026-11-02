#!/usr/bin/env python3
"""Сбор состояния сервера для страницы статуса (cron, раз в минуту): python3 -I collect.py DATA_DIR
Пишет DATA_DIR/status.json (то, что видит посетитель) и status-history.json (счётчик минут по дням).
В JSON — только обезличенные цифры: аптайм, нагрузка, % памяти и диска. Ни IP, ни портов, ни процессов."""
import datetime as dt, json, os, sys, tempfile

data = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(data, exist_ok=True)
now = dt.datetime.now(dt.timezone.utc)


def write(name, obj):
    fd, tmp = tempfile.mkstemp(dir=data, prefix=".tmp-")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, separators=(",", ":"))
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(data, name))


def meminfo():
    m = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":", 1)
        m[k] = int(v.split()[0])
    total = m.get("MemTotal", 1)
    return 100.0 * (total - m.get("MemAvailable", total)) / total


hp = os.path.join(data, "status-history.json")
try:
    h = json.load(open(hp))
    assert isinstance(h.get("days"), dict)
except Exception:
    h = {"first": now.isoformat(timespec="seconds"), "days": {}}
today = now.date().isoformat()
h["days"][today] = h["days"].get(today, 0) + 1
keep = sorted(h["days"])[-90:]
h["days"] = {k: h["days"][k] for k in keep}
write("status-history.json", h)

first = dt.datetime.fromisoformat(h["first"])
days = []
for k in keep:
    d0 = dt.datetime.fromisoformat(k + "T00:00:00+00:00")
    start = max(d0, first)
    end = min(d0 + dt.timedelta(days=1), now)
    expected = max(1, int((end - start).total_seconds() // 60))
    days.append({"d": k, "p": round(min(100.0, 100.0 * h["days"][k] / expected), 2)})

st = os.statvfs("/")
disk = 100.0 * (1 - st.f_bavail / st.f_blocks) if st.f_blocks else 0.0
write("status.json", {
    "updated": now.isoformat(timespec="seconds"),
    "uptime_s": int(float(open("/proc/uptime").read().split()[0])),
    "load": [round(float(x), 2) for x in open("/proc/loadavg").read().split()[:3]],
    "cpus": os.cpu_count() or 1,
    "mem_pct": round(meminfo(), 1),
    "disk_pct": round(disk, 1),
    "days": days,
})
