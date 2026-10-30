#!/usr/bin/env bash
# Собирает install.sh из install.sh.in + lib/provision.py (один файл для запуска одной командой).
set -euo pipefail
cd "$(dirname "$0")"
grep -q '^PYEOF$' lib/provision.py && { echo "provision.py не должен содержать строку PYEOF"; exit 1; }
python3 - <<'EOF'
tpl = open("install.sh.in").read()
py = open("lib/provision.py").read().rstrip("\n")
assert tpl.count("@@PROVISION@@") == 1
open("install.sh", "w").write(tpl.replace("@@PROVISION@@", py))
EOF
chmod +x install.sh
bash -n install.sh && echo "install.sh собран: $(wc -l < install.sh) строк"
