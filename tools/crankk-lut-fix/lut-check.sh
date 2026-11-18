#!/bin/sh
# PAUL_CRANKK_SAFE_LUT_V1 short command: check   usage: curl -fsSL https://node.paulnetwork.io/lut-check | sh
F=/tmp/paul-lut-fix-$(id -u).sh
U=https://node.paulnetwork.io/lut-fix
rm -f "$F"
if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$F" "$U"; else wget -qO "$F" "$U"; fi
if ! head -2 "$F" 2>/dev/null | grep -q PAUL_CRANKK_SAFE_LUT_V1; then echo "[paul-lut] ERROR: download of $U failed"; exit 1; fi
# give the script a real terminal (needed if sudo asks for a password), else run without
if ( exec </dev/tty ) 2>/dev/null; then exec sh "$F" --check </dev/tty; else exec sh "$F" --check </dev/null; fi
