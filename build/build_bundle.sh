#!/usr/bin/env bash
# Costruisce il pacchetto portabile per Windows in dist/RemoteDesk-<versione>.zip, da Linux.
# Requisiti: python3 + pip, curl, unzip, zip, mingw-w64 (x86_64-w64-mingw32-gcc e windres).
#   Ubuntu/Debian:  sudo apt install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 zip unzip
set -euo pipefail
cd "$(dirname "$0")"
PYVER=3.12.10
VERSION=$(python3 -c "import re;print(re.search(r'VERSION = \"(.+?)\"', open('../app/rd/common.py').read()).group(1))")
OUT=out/RemoteDesk
rm -rf out && mkdir -p "$OUT/runtime" dl

# 1) Python per Windows (pacchetto ufficiale "python" su NuGet: contiene python.exe/pythonw.exe e la libreria standard)
[ -f dl/python.nupkg ] || curl -sSL -o dl/python.nupkg "https://api.nuget.org/v3-flatcontainer/python/$PYVER/python.$PYVER.nupkg"
rm -rf dl/nup && mkdir dl/nup && unzip -q dl/python.nupkg 'tools/*' -d dl/nup
cp -r dl/nup/tools/. "$OUT/runtime/"
( cd "$OUT/runtime" && rm -rf tcl Lib/test Lib/tkinter Lib/idlelib Lib/turtledemo Lib/turtle.py include libs \
    Lib/ensurepip Scripts DLLs/_tkinter.pyd DLLs/tcl86t.dll DLLs/tk86t.dll Lib/site-packages/pip* )

# 2) Librerie (wheel binarie per Windows 64 bit)
pip install -q --no-compile --target "$OUT/runtime/Lib/site-packages" --platform win_amd64 \
    --python-version 3.12 --implementation cp --only-binary=:all: -r requirements-windows.txt
pip download -q --no-deps --platform win_amd64 --python-version 3.12 --implementation cp \
    --only-binary=:all: PyAudioWPatch -d dl/pa
unzip -qo dl/pa/pyaudiowpatch-*.whl -d "$OUT/runtime/Lib/site-packages"
rm -rf "$OUT/runtime/Lib/site-packages/numpy"*   # non serve (e sotto Wine si blocca)

# 3) RemoteDesk.exe (piccolo avviatore C con icona)
x86_64-w64-mingw32-windres launcher.rc -O coff -o launcher.res
x86_64-w64-mingw32-gcc -O2 -municode -mwindows -s -Wl,--no-insert-timestamp launcher.c launcher.res -o "$OUT/RemoteDesk.exe"

# 4) Applicazione e istruzioni
cp -r ../app "$OUT/app"
find "$OUT" -name __pycache__ -prune -exec rm -rf {} \;
python3 - "$OUT/LEGGIMI.txt" <<'PY'
import sys; s = open("LEGGIMI.txt", encoding="utf-8-sig").read().replace("\r\n", "\n")
open(sys.argv[1], "w", encoding="utf-8-sig", newline="\r\n").write(s)
PY

# 5) Zip in dist/ (con impronta SHA-256)
mkdir -p ../dist
rm -f "../dist/RemoteDesk-$VERSION.zip"
( cd out && zip -qrX9 "../../dist/RemoteDesk-$VERSION.zip" RemoteDesk )
( cd ../dist && sha256sum "RemoteDesk-$VERSION.zip" > "RemoteDesk-$VERSION.zip.sha256" )
echo "Creato dist/RemoteDesk-$VERSION.zip"

# Link di download diretto nel README
sed -i -E "s#(dist/)?RemoteDesk-[0-9]+\.[0-9]+\.[0-9]+\.zip#\1RemoteDesk-$VERSION.zip#g; s#Scarica RemoteDesk [0-9]+\.[0-9]+\.[0-9]+ per#Scarica RemoteDesk $VERSION per#" ../README.md

# 6) Manifesto degli aggiornamenti FIRMATO (dist/latest.json). Serve la chiave privata di rilascio:
#    RD_RELEASE_KEY=/percorso/remotedesk-release.key ./build/build_bundle.sh
#    La chiave NON va mai messa nella repository.
if [ -n "${RD_RELEASE_KEY:-}" ]; then
  python3 - "$VERSION" "${RD_UPDATE_BASE:-https://raw.githubusercontent.com/tbkon3/remote-desk-tbk/main/dist}" <<'PY'
import base64, hashlib, json, os, re, sys, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ver, base = sys.argv[1], sys.argv[2].rstrip("/")
z = f"../dist/RemoteDesk-{ver}.zip"
key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(open(os.environ["RD_RELEASE_KEY"]).read().strip()))
log = open("../CHANGELOG.md", encoding="utf-8").read()
m = re.search(r"## " + re.escape(ver) + r"\n(.*?)(\n## |\Z)", log, re.S)
notes = re.sub(r"[*`]", "", m.group(1)).strip() if m else ""
body = {"version": ver, "file": os.path.basename(z), "url": f"{base}/{os.path.basename(z)}",
        "sha256": hashlib.sha256(open(z, "rb").read()).hexdigest(), "size": os.path.getsize(z),
        "date": time.strftime("%Y-%m-%d"), "notes": notes[:1500]}
canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
body["sig"] = base64.b64encode(key.sign(canon)).decode()
json.dump(body, open("../dist/latest.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("Creato dist/latest.json (firmato)")
PY
else
  echo "ATTENZIONE: RD_RELEASE_KEY non impostata: dist/latest.json non aggiornato (i PC non vedranno questa versione)"
fi
