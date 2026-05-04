#!/usr/bin/env bash
# Stage SLEIGH spec files for the pyre web frontend.
#
# Two modes:
#   1. Copy pre-compiled .sla/.ldefs/.cspec/.pspec from a source tree
#      laid out as `<src>/Ghidra/Processors/<arch>/data/languages/...`
#      (this is what resources/decompiler/specfiles/ already provides
#      for x86 + AARCH64).
#   2. (TODO) Build .sla files from .slaspec by invoking sleighc on
#      a Ghidra source clone — needed to ship every architecture
#      Ghidra supports. Wire this up once Java/gradle are provisioned.
#
# Output layout (matches what the worker's lazy-mount expects):
#   dist/<processor>/data/languages/*.{sla,ldefs,cspec,pspec,sinc,opinion}
#   dist/manifest.json    {files: [{path, size}, ...]}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/dist"
SRC="${1:-$SCRIPT_DIR/../../resources/decompiler/specfiles}"

if [[ ! -d "$SRC/Ghidra/Processors" ]]; then
    echo "error: $SRC does not look like a Ghidra processor tree" >&2
    echo "expected layout: <src>/Ghidra/Processors/<arch>/data/languages/" >&2
    exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "[stage] copying spec files from $SRC..."
copied=0
for proc_dir in "$SRC"/Ghidra/Processors/*/; do
    proc="$(basename "$proc_dir")"
    src_lang="$proc_dir/data/languages"
    [[ -d "$src_lang" ]] || continue

    dst_lang="$OUT_DIR/$proc/data/languages"
    mkdir -p "$dst_lang"

    # Copy the file types the decompiler reads at runtime. .slaspec /
    # .sinc are skipped — those are SLEIGH source, only needed when
    # compiling .sla. Once we wire sleighc into mode (2), .slaspec
    # will be consumed at build time and won't ship.
    for ext in sla ldefs cspec pspec opinion; do
        for f in "$src_lang"/*."$ext"; do
            [[ -f "$f" ]] || continue
            cp "$f" "$dst_lang/"
            copied=$((copied + 1))
        done
    done
done
echo "[stage] copied $copied files across $(ls -1 "$OUT_DIR" 2>/dev/null | wc -l) processors"

# Emit a flat manifest the worker uses to register LazyFile entries.
# Sizes let emscripten pre-stat without an extra HEAD request.
echo "[stage] writing manifest.json..."
python3 - "$OUT_DIR" <<'PY'
import json, os, sys
root = sys.argv[1]
files = []
for dirpath, _, fnames in os.walk(root):
    for fn in fnames:
        full = os.path.join(dirpath, fn)
        rel = os.path.relpath(full, root)
        if rel == "manifest.json":
            continue
        files.append({"path": rel.replace(os.sep, "/"), "size": os.path.getsize(full)})
files.sort(key=lambda e: e["path"])
with open(os.path.join(root, "manifest.json"), "w") as f:
    json.dump({"files": files}, f, indent=2)
print(f"[stage] manifest: {len(files)} files")
PY

echo "[stage] done: $OUT_DIR"
du -sh "$OUT_DIR"
