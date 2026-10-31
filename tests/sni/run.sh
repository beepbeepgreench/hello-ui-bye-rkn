#!/usr/bin/env bash
# Офлайн-тесты lib/sni.py: локальный CA + openssl s_server / python TLS на 127.0.0.x.
# Запуск: bash tests/sni/run.sh   (PYTHON=/usr/bin/python3 bash tests/sni/run.sh — другой интерпретатор)
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
PY=${PYTHON:-python3}
SNI="$PY -I $ROOT/lib/sni.py"
T=$(mktemp -d)
P=$(( 20000 + RANDOM % 20000 ))
PIDS=()
cleanup(){ for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
ko(){ echo "  FAIL  $*"; fail=$((fail+1)); }

echo "== python: $($PY -V 2>&1), $(openssl version), порт $P, tmp $T"

# ---------- CA и сертификаты ----------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/ca.key" -out "$T/ca.crt" \
  -days 7 -subj "/CN=SNI Test CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" 2>/dev/null
leaf(){ # name sans...
  local n=$1; shift; local san; san=$(printf 'DNS:%s,' "$@"); san=${san%,}
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/$n.key" -out "$T/$n.csr" -subj "/CN=$1" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$san" > "$T/$n.ext"
  openssl x509 -req -in "$T/$n.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial -days 7 -extfile "$T/$n.ext" -out "$T/$n.crt" 2>/dev/null
}
leaf good good.test www.good.test www.apple.test
leaf tls12 tls12.test
leaf noh2 noh2.test
leaf other other.test
leaf nox nox.test
leaf rel rel.test
leaf cross cross.test
leaf slow slow.test
leaf forbid forbid.test

# ---------- серверы (все на одном порту, разные 127.0.0.x — это же «соседи по /24») ----------
srv(){ openssl s_server -quiet -www -accept "$1:$P" -cert "$T/$2.crt" -key "$T/$2.key" "${@:3}" </dev/null >/dev/null 2>&1 & PIDS+=($!); }
srv 127.0.0.2 good  -tls1_3 -alpn h2
srv 127.0.0.3 tls12 -tls1_2 -alpn h2
srv 127.0.0.4 noh2  -tls1_3
srv 127.0.0.5 other -tls1_3 -alpn h2
srv 127.0.0.6 nox   -tls1_3 -alpn h2 -groups P-256
fx(){ $PY -I tests/sni/fixture_server.py "$1" "$P" "$T/$2.crt" "$T/$2.key" "${@:3}" >/dev/null 2>&1 & PIDS+=($!); }
fx 127.0.0.8  rel    301 /de/
fx 127.0.0.9  cross  302 https://shop.elsewhere.example/
fx 127.0.0.10 slow   200 --delay 0.3
fx 127.0.0.11 forbid 403
# 127.0.0.7 — закрытый порт
for _ in $(seq 1 50); do
  n=0; for a in 2 3 4 5 6 8 9 10 11; do (exec 3<>"/dev/tcp/127.0.0.$a/$P") 2>/dev/null && n=$((n+1)); done
  [ "$n" -eq 9 ] && break; sleep 0.2
done

R="--port $P --cafile $T/ca.crt --timeout 3"
for m in good.test:2 www.good.test:2 www.apple.test:2 tls12.test:3 noh2.test:4 other.test:5 wrong.test:5 \
         nox.test:6 closed.test:7 rel.test:8 cross.test:9 slow.test:10 forbid.test:11; do
  R="$R --resolve ${m%%:*}:127.0.0.${m##*:}"
done
R="$R --resolve cdn.test:104.16.1.1 --resolve fastly.test:151.101.1.1"

# ---------- check ----------
echo "== check"
expect(){ # domain exit_code regex [extra args]
  local d=$1 want=$2 re=$3; shift 3
  local out rc; out=$($SNI check "$d" $R "$@" 2>&1); rc=$?
  if [ "$rc" = "$want" ] && grep -Eq -- "$re" <<<"$out"; then ok "check $d → $rc ($(sed -n 2p <<<"$out" | sed 's/^ *- //'))"
  else ko "check $d: код $rc (ждали $want), вывод:"; sed 's/^/        /' <<<"$out"; fi
}
expect good.test        0 ": OK"
expect www.good.test    0 ": OK"
expect tls12.test       2 "не поддерживает TLS 1.3"
expect noh2.test        2 "ALPN h2"
expect wrong.test       2 "сертификат выдан на другое имя"
expect closed.test      2 "порт $P закрыт"
expect nox.test         2 "X25519"
expect cdn.test         2 "CDN Cloudflare"
expect fastly.test      2 "CDN Fastly"
expect www.apple.test   1 "популярное"
expect rel.test         0 ": OK"
expect cross.test       2 "редиректит на другой сайт"
expect slow.test        1 "далеко от сервера"
expect forbid.test      1 "HTTP 403"
expect forbid.test      0 ": OK" --no-http
expect 1.2.3.4          2 "некорректное доменное имя"
expect nonexistent.invalid 2 "нет DNS A-записи"
out=$($SNI check good.test --port "$P" --resolve good.test:127.0.0.2 --timeout 3 2>&1); rc=$?
[ $rc = 2 ] && grep -q "доверенными центрами" <<<"$out" && ok "check good.test без --cafile → 2 (чужой CA)" || ko "без cafile: $rc $out"
js=$($SNI check good.test $R --json); rc=$?
$PY -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["verdict_name"]=="OK" and d["alpn"]=="h2" and d["x25519"] and d["tls13"] and d["http_status"]==200, d' "$js" \
  && [ $rc = 0 ] && ok "check --json: поля корректны" || ko "check --json: $js"

# ---------- scan ----------
echo "== scan (соседи 127.0.0.1/24 + свой список)"
t0=$(date +%s)
out=$($SNI scan --neighbors 127.0.0.1 --candidates tls12.test,cdn.test,www.apple.test,slow.test $R 2>"$T/scan.err"); rc=$?
dt=$(( $(date +%s) - t0 ))
echo "$out" | sed 's/^/        /'; sed 's/^/        [stderr] /' "$T/scan.err"
first=$(awk '$1=="1"{print $2" "$3}' <<<"$out")
[[ $first == *" сосед" ]] && ok "scan: #1 — сосед, прошедший проверку ($first)" || ko "scan: #1 не сосед: $first"
grep -q "other.test" <<<"$out" && ok "scan: имя other.test найдено в сертификате соседа .5" || ko "scan: other.test не найден"
grep -Eq "^ +[0-9]+ +www.apple.test .*WARN" <<<"$out" && ok "scan: www.apple.test в таблице с WARN" || ko "scan: apple"
grep -q "отброшено.*tls12.test" <<<"$out" && grep -q "cdn.test" <<<"$out" && ok "scan: FAIL-кандидаты отброшены" || ko "scan: отброшенные"
[ $dt -le 60 ] && ok "scan уложился в ${dt} с (cap 60)" || ko "scan шёл ${dt} с"
js=$($SNI scan --neighbors 127.0.0.1 --candidates tls12.test $R --json 2>/dev/null)
$PY -c '
import json,sys; rows=json.loads(sys.argv[1]); v=[r["verdict"] for r in rows]
n=[r for r in rows if r["neighbor"]]; assert rows[0]["neighbor"] and rows[0]["verdict"]==0, rows[0]
names={r["domain"] for r in n}; assert {"good.test","other.test","nox.test","rel.test"} <= names, names
assert all(r["verdict"]==2 for r in rows if r["domain"] in ("nox.test","tls12.test","cross.test")), rows
' "$js" && ok "scan --json: ранжирование и вердикты соседей" || ko "scan --json"

# ---------- pick: не интерактивно ----------
echo "== pick (без tty)"
d=$(setsid -w $SNI pick --candidates www.good.test,tls12.test $R </dev/null 2>/dev/null); rc=$?
[ $rc = 0 ] && [ "$d" = "www.good.test" ] && ok "pick без tty → $d" || ko "pick без tty: rc=$rc '$d'"
d=$(setsid -w $SNI pick --candidates www.good.test,good.test --default good.test $R </dev/null 2>/dev/null); rc=$?
[ $rc = 0 ] && [ "$d" = "good.test" ] && ok "pick --default (OK) сохраняет текущий → $d" || ko "pick default: rc=$rc '$d'"
d=$(setsid -w $SNI pick --candidates tls12.test,cdn.test,www.apple.test $R </dev/null 2>/dev/null); rc=$?
[ $rc = 2 ] && [ -z "$d" ] && ok "pick без OK-вариантов → код 2, stdout пуст" || ko "pick none: rc=$rc '$d'"
d=$($SNI pick --non-interactive --candidates good.test $R 2>/dev/null); rc=$?
[ $rc = 0 ] && [ "$d" = "good.test" ] && ok "pick --non-interactive → $d" || ko "pick --non-interactive: $rc '$d'"

# ---------- pick: интерактивно через pty ----------
echo "== pick (pty)"
steps='[["Enter = ","wrong.test"],["выберите другой","www.apple.test"],["Использовать? [y/N]","n"],["Enter = ","99"],["нет номера","abc"],["некорректное","" ]]'
$PY -I tests/sni/pty_pick.py "$T/pick1.out" "$steps" -- $PY -I lib/sni.py pick --candidates www.good.test,slow.test,tls12.test $R >"$T/pick1.tty" 2>&1; rc=$?
d=$(cat "$T/pick1.out")
if [ $rc = 0 ] && [ "$d" = "www.good.test" ] && grep -q "сертификат выдан на другое имя" "$T/pick1.tty" && grep -q "нет номера 99" "$T/pick1.tty"; then
  ok "pty: FAIL отклонён, WARN→n, неверный номер, Enter → #1; stdout='$d'"
else ko "pty сценарий 1: rc=$rc stdout='$d'"; sed 's/^/        /' "$T/pick1.tty"; fi
steps='[["Enter = ","www.apple.test"],["Использовать? [y/N]","да"]]'
$PY -I tests/sni/pty_pick.py "$T/pick2.out" "$steps" -- $PY -I lib/sni.py pick --candidates good.test $R >"$T/pick2.tty" 2>&1; rc=$?
d=$(cat "$T/pick2.out")
[ $rc = 0 ] && [ "$d" = "www.apple.test" ] && ok "pty: свой домен с WARN, подтверждение → stdout='$d'" || { ko "pty 2: rc=$rc '$d'"; sed 's/^/        /' "$T/pick2.tty"; }
steps='[["Enter = ","2"]]'
$PY -I tests/sni/pty_pick.py "$T/pick3.out" "$steps" -- $PY -I lib/sni.py pick --candidates good.test,rel.test $R >"$T/pick3.tty" 2>&1; rc=$?
d=$(cat "$T/pick3.out"); want=$(awk '$1=="2"{print $2}' "$T/pick3.tty" | head -1)
[ $rc = 0 ] && [ -n "$want" ] && [ "$d" = "$want" ] && ok "pty: выбор номера 2 → '$d'" || { ko "pty 3: rc=$rc '$d' want '$want'"; sed 's/^/        /' "$T/pick3.tty"; }
steps='[["Enter = ","good.test"]]'
$PY -I tests/sni/pty_pick.py "$T/pick4.out" "$steps" -- $PY -I lib/sni.py pick --candidates rel.test $R >"$T/pick4.tty" 2>&1; rc=$?
[ $rc = 0 ] && [ "$(cat "$T/pick4.out")" = "good.test" ] && [ "$(wc -l < "$T/pick4.out")" = 1 ] && ok "pty: свой OK-домен принят, stdout ровно одна строка" || ko "pty 4: rc=$rc"

echo "== итог: PASS $pass, FAIL $fail"
[ "$fail" = 0 ]
