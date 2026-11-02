#!/usr/bin/env python3
"""Обновление курсов для сайта (cron, раз в час): python3 -I fetch.py DATA_DIR
Источник: open.er-api.com (без ключа). При любой ошибке старый rates.json остаётся как есть (код 1).
Для тестов: RATES_URL=file:///путь.json, SEED_URL=…{y}/{m}/{d}… (история за 30 дней, архив ЦБ РФ)."""
import datetime as dt, json, os, sys, tempfile, urllib.request

data = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(data, exist_ok=True)
CODES = ["USD", "EUR", "GBP", "CNY", "JPY", "CHF", "TRY", "KZT", "BYN", "RUB", "PLN", "AED"]
URL = os.environ.get("RATES_URL", "https://open.er-api.com/v6/latest/USD")
today = dt.date.today()


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (rates-cache)"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read(2_000_000))


def write(name, obj):
    fd, tmp = tempfile.mkstemp(dir=data, prefix=".tmp-")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, separators=(",", ":"))
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(data, name))


try:
    j = get(URL)
    assert j.get("result") == "success", "result != success"
    rates = {c: float(j["rates"][c]) for c in CODES if c in j.get("rates", {})}
    assert all(v > 0 for v in rates.values()) and len(rates) >= 8 and "RUB" in rates and abs(rates["USD"] - 1) < 1e-9
    updated = j.get("time_last_update_unix")
    updated = dt.datetime.fromtimestamp(int(updated), dt.timezone.utc) if updated else dt.datetime.now(dt.timezone.utc)
except Exception as e:  # сеть/формат — оставляем последний удачный файл
    print(f"rates: источник недоступен или ответ некорректен ({e}); оставляю прежние данные", file=sys.stderr)
    sys.exit(1)

hp = os.path.join(data, "rates-history.json")
try:
    hist = json.load(open(hp))
    assert isinstance(hist, dict)
except Exception:
    hist = {}
meta = hist.pop("_meta", {})
if len(hist) < 5 and not meta.get("seeded"):
    # один раз подтягиваем ~30 дней истории (архив ЦБ РФ в JSON), чтобы графики не были пустыми
    meta["seeded"] = True
    seed = os.environ.get("SEED_URL", "https://www.cbr-xml-daily.ru/archive/{y}/{m}/{d}/daily_json.js")
    fails = 0
    for back in range(30, 0, -1):
        day = today - dt.timedelta(days=back)
        if day.weekday() >= 5 or day.isoformat() in hist:
            continue
        try:
            v = get(seed.format(y=day.year, m=f"{day.month:02d}", d=f"{day.day:02d}"))["Valute"]
            rub = {c: float(v[c]["Value"]) / float(v[c]["Nominal"]) for c in CODES if c in v}
            usd_rub = rub["USD"]
            row = {c: usd_rub / r for c, r in rub.items() if r > 0}
            row["RUB"], row["USD"] = usd_rub, 1.0
            hist[day.isoformat()] = row
            fails = 0
        except Exception as e:
            fails += 1
            if fails >= 3:
                print(f"rates: история не загружена ({e})", file=sys.stderr)
                break
hist[today.isoformat()] = dict(hist.get(today.isoformat(), {}), **rates)
keep = sorted(k for k in hist if len(k) == 10)[-45:]
hist = {k: hist[k] for k in keep}
write("rates-history.json", dict(hist, _meta=meta))
write("rates.json", {"updated": updated.isoformat(timespec="seconds"),
                     "fetched": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                     "usd": rates, "hist": hist})
print(f"rates: обновлено ({len(rates)} валют)")
