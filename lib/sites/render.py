#!/usr/bin/env python3
"""Сборка сайта-маски из шаблона lib/sites/<id>/ для домена.

  python3 -I render.py ID SRC_DIR OUT_DIR DOMAIN

* язык: ru для .ru/.su/.рф (xn--p1ai), иначе en;
* все «случайные» детали (имя, цвет, проекты, даты) выводятся из хэша домена — на разных
  серверах сайты различаются, а при повторной сборке на одном сервере сайт тот же;
* {{KEY}} в файлах шаблона заменяется из i18n.json[lang] и вычисленных переменных;
* печатает список созданных файлов (относительные пути) — это манифест для маркера.
"""
import datetime as dt, hashlib, html, json, os, random, sys, time

TID, SRC, OUT, DOMAIN = sys.argv[1:5]
TDIR = os.path.join(SRC, TID)
LANG = "ru" if DOMAIN.endswith((".ru", ".su", ".xn--p1ai", ".рф")) else "en"
SEED = int(hashlib.sha256(f"{DOMAIN}|{TID}".encode()).hexdigest(), 16)
rng = random.Random(SEED)
TODAY = dt.date.today()
I18N = json.load(open(os.path.join(TDIR, "i18n.json"), encoding="utf-8"))
T = dict(I18N.get("common", {}), **I18N[LANG])


def label(d):
    """Человеческое имя бренда из домена: status.devbranches.ru → Devbranches."""
    parts = d.split(".")
    core = parts[-2] if len(parts) >= 2 else parts[0]
    if core.startswith("xn--"):
        try:
            core = core.encode().decode("idna")
        except Exception:
            core = core[4:]
    return " ".join(w.capitalize() for w in core.replace("_", "-").split("-") if w) or "Studio"


def ago(days):
    return TODAY - dt.timedelta(days=days)


def fmt_date(d):
    if LANG == "ru":
        m = ["января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября",
             "октября", "ноября", "декабря"][d.month - 1]
        return f"{d.day} {m} {d.year}"
    return d.strftime("%-d %B %Y")


ACCENTS = [  # (светлая тема, тёмная тема)
    ("#1f5f8b", "#7fb8e0"), ("#7a3e9d", "#c39be0"), ("#0f6b55", "#6cc9ae"),
    ("#8a4b14", "#e0a668"), ("#a3324a", "#ee8fa1"), ("#3d4fb3", "#9aa7f0"),
]
acc, acc_d = rng.choice(ACCENTS)
V = {"DOMAIN": DOMAIN, "LANG": LANG, "YEAR": str(TODAY.year), "BRAND": label(DOMAIN),
     "ACC": acc, "ACC_D": acc_d, "UPDATED": fmt_date(ago(rng.randint(9, 40)))}


# ---------------- визитка ----------------
def build_card():
    first, last = rng.choice(T["names"])
    V["NAME"] = f"{first} {last}"
    V["FIRST"] = first
    V["INITIALS"] = first[0] + last[0]
    V["SINCE"] = str(TODAY.year - rng.randint(6, 12))
    base = ".".join(DOMAIN.split(".")[-2:])  # почта на основном домене, не на поддомене
    V["MAIL"] = f"{rng.choice(['hello', 'studio', 'mail', 'work'])}@{base}"
    projects = rng.sample(T["projects"], 4)
    h0 = rng.randrange(360)
    hues = [(h0 + i * 83) % 360 for i in range(4)]  # заметно разные цвета у соседних плиток
    tiles = []
    for (name, kind, text), hue in zip(projects, hues):
        layout = rng.choice(["shop", "app", "docs", "landing"])
        tiles.append(f'''<article class="work">
  <div class="shot shot-{layout}" style="--h:{hue}" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i></div>
  <h3>{html.escape(name)}</h3><p class="kind">{html.escape(kind)}</p><p>{html.escape(text)}</p>
</article>''')
    V["WORKS"] = "\n".join(tiles)
    services = T["services"]
    V["SERVICES"] = "\n".join(f"<li><h3>{html.escape(a)}</h3><p>{html.escape(b)}</p></li>" for a, b in services)
    steps = T["steps"]
    V["STEPS"] = "\n".join(f"<li><strong>{html.escape(a)}</strong> {html.escape(b)}</li>" for a, b in steps)
    # страница «работы»: более длинные описания тех же проектов + годы
    rows = []
    year = TODAY.year
    for name, kind, text in projects + rng.sample([p for p in T["projects"] if p not in projects], 2):
        year -= rng.randint(0, 1)
        rows.append(f"<tr><td>{year}</td><td><strong>{html.escape(name)}</strong><br><span>{html.escape(text)}</span></td><td>{html.escape(kind)}</td></tr>")
    V["WORKROWS"] = "\n".join(rows)
    return ["", "work"]


# ---------------- статус ----------------
def build_status():
    V["HOST"] = rng.choice(T["hosts"])
    log = []
    days = sorted(rng.sample(range(5, 170), 5))
    for n, d in enumerate(days):
        title, text = T["events"][n % len(T["events"])]
        log.append(f'<li><time datetime="{ago(d).isoformat()}">{fmt_date(ago(d))}</time>'
                   f'<h3>{html.escape(title)}</h3><p>{html.escape(text)}</p></li>')
    V["EVENTS"] = "\n".join(log)
    return ["", "history"]


# ---------------- курсы ----------------
def build_rates():
    V["BASE"] = "RUB" if LANG == "ru" else "USD"
    V["NAMES_JSON"] = json.dumps(T["currencies"], ensure_ascii=False)
    return ["", "about"]


pages = {"card": build_card, "status": build_status, "rates": build_rates}[TID]()
ctx = dict(T)
ctx.update(V)
ctx = {k: v for k, v in ctx.items() if isinstance(v, str)}


def fill(text, name):
    out, i = [], 0
    while True:
        j = text.find("{{", i)
        if j < 0:
            out.append(text[i:]); break
        k = text.find("}}", j)
        key = text[j + 2:k]
        if key not in ctx:
            sys.exit(f"render: {TID}/{name}: нет значения для {{{{{key}}}}}")
        out.append(text[i:j]); out.append(ctx[key]); i = k + 2
    return "".join(out)


for _k in list(ctx):  # строки из i18n могут ссылаться на переменные ({{SINCE}})
    if "{{" in ctx[_k]:
        ctx[_k] = fill(ctx[_k], "i18n:" + _k)

made = []
os.makedirs(OUT, exist_ok=True)
for name in sorted(os.listdir(TDIR)):
    if name in ("i18n.json",) or name.endswith(".py") or name.startswith("."):
        continue
    src = os.path.join(TDIR, name)
    if not os.path.isfile(src):
        continue
    text = open(src, encoding="utf-8").read()
    if name.endswith((".html", ".css", ".js", ".svg")):
        text = fill(text, name)
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(text)
    made.append(name)

with open(os.path.join(OUT, "robots.txt"), "w") as f:
    f.write(f"User-agent: *\nAllow: /\nSitemap: https://{DOMAIN}/sitemap.xml\n")
with open(os.path.join(OUT, "sitemap.xml"), "w") as f:
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
    for p in pages:
        f.write(f"  <url><loc>https://{DOMAIN}/{p}</loc></url>\n")
    f.write("</urlset>\n")
made += ["robots.txt", "sitemap.xml"]

# «живые» даты изменения: файлы правились в прошлые недели, а не в момент установки
now = time.time()
for n, name in enumerate(made):
    t = now - (rng.randint(12, 160) * 86400) - rng.randint(0, 86000)
    os.utime(os.path.join(OUT, name), (t, t))
    os.chmod(os.path.join(OUT, name), 0o644)
print("\n".join(made))
