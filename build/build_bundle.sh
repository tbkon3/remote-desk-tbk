#!/usr/bin/env bash
# Costruisce il pacchetto portabile per Windows (RemoteDesk-<versione>.zip) da Linux.
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
x86_64-w64-mingw32-gcc -O2 -municode -mwindows -s launcher.c launcher.res -o "$OUT/RemoteDesk.exe"

# 4) Applicazione e istruzioni
cp -r ../app "$OUT/app"
find "$OUT" -name __pycache__ -prune -exec rm -rf {} \;
python3 - "$OUT/LEGGIMI.txt" <<'PY'
import sys; s = open("LEGGIMI.txt", encoding="utf-8-sig").read().replace("\r\n", "\n")
open(sys.argv[1], "w", encoding="utf-8-sig", newline="\r\n").write(s)
PY

# 5) Zip
( cd out && zip -qr9 "../RemoteDesk-$VERSION.zip" RemoteDesk )
echo "Creato build/RemoteDesk-$VERSION.zip"
