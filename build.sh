#!/usr/bin/env bash
# Собирает install.sh (один файл) из install.sh.in + lib/*.
#   VERSION=v1.0.0 REPO=beepbeepgreench/hello-ui-bye-rkn bash build.sh
# SELF_URL указывает на ТЕГ релиза, поэтому всем раздаётся одна неизменная версия.
set -euo pipefail
cd "$(dirname "$0")"
VERSION=${VERSION:-$(cat VERSION 2>/dev/null || echo v0.0.0-dev)}
REPO=${REPO:-beepbeepgreench/hello-ui-bye-rkn}
SELF_URL="https://raw.githubusercontent.com/${REPO}/${VERSION}/install.sh"
for f in lib/provision.py lib/sni.py; do
  [ -f "$f" ] || { echo "нет $f"; exit 1; }
  if grep -q '^PYEOF$' "$f"; then echo "$f не должен содержать строку PYEOF"; exit 1; fi
done
# шаблоны сайтов-масок (lib/sites) — детерминированный tar.gz в base64, вшивается вместо @@SITES@@
SITES_B64=$(tar --sort=name --mtime='2026-01-01 00:00Z' --owner=0 --group=0 --numeric-owner \
  --exclude='__pycache__' --exclude='*.pyc' -C lib/sites -cf - . | gzip -9n | base64 -w 76)
export SITES_B64
VERSION="$VERSION" SELF_URL="$SELF_URL" python3 - <<'EOF'
import os, re
s = open("install.sh.in").read()
def lib_sh(m):
    body = open(f"lib/{m.group(1)}.sh").read()
    body = re.sub(r"^#!.*\n", "", body)          # shebang модуля не нужен внутри
    return body.rstrip("\n")
s = re.sub(r"@@LIB_SH:(\w+)@@", lib_sh, s)
for key, path in (("@@PROVISION@@", "lib/provision.py"), ("@@SNI@@", "lib/sni.py")):
    assert s.count(key) == 1, key
    s = s.replace(key, open(path).read().rstrip("\n"))
assert s.count("@@SITES@@") == 1, "@@SITES@@"
s = s.replace("@@SITES@@", os.environ["SITES_B64"])
s = s.replace("@@VERSION@@", os.environ["VERSION"]).replace("@@SELF_URL@@", os.environ["SELF_URL"])
assert "@@" not in s.replace("${SELF_URL#@@}", ""), "остались незаменённые маркеры"
open("install.sh", "w").write(s)
EOF
chmod +x install.sh
bash -n install.sh
echo "install.sh собран: ${VERSION}, $(wc -l < install.sh) строк, SELF_URL=${SELF_URL}"
