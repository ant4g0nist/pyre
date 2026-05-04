# Pyre

Ghidra's C++ decompiler running in your browser.

Drag in an ELF, Mach-O, PE, or `.wasm`. Pyre parses the binary, lazy-loads
the SLEIGH spec for its architecture, and decompiles functions on demand.
Navigate via a function list, Cmd-click on call sites in Monaco to follow
calls into new tabs, and read cross-references in the side panel.

Everything runs client-side. Binaries never leave the browser; there is no
server, no upload, no telemetry.

## Status

Alpha. The core pipeline (binary parse → wasm decompile → Monaco render
→ navigation) works on x86 (32/64), AArch64, and WebAssembly modules.
Other architectures Ghidra supports compile fine but are not bundled
in the default spec set yet — see [Roadmap](#roadmap).

## Quick start

You need:

- Node 20+
- [emsdk](https://emscripten.org/docs/getting_started/downloads.html)
  on your `PATH` (or sourced via `emsdk_env.sh`)
- A staged set of SLEIGH specs — pre-built `.sla` files for one or
  more architectures (see step 2)

```bash
# 1. Build the wasm module (~30 s clean, ~5 s incremental)
./decompiler-wasm/build.sh
# → decompiler-wasm/dist/pyre_decompiler.{js,wasm}

# 2. Stage SLEIGH specs from a directory laid out as
#    Ghidra/Processors/<arch>/data/languages/...
./specs/stage-specs.sh /path/to/your/Ghidra/source/tree
# → specs/dist/<arch>/data/languages/*.{sla,ldefs,cspec,pspec}
# → specs/dist/manifest.json

# 3. Run the web frontend
cd web
npm install
npm run dev    # http://localhost:5173
```

The `web/public/decompiler` and `web/public/specs` symlinks point at
the build outputs from steps 1 and 2.

## Docker

If you'd rather not install emsdk + Node locally:

```bash
docker build -t pyre-dev -f docker/Dockerfile .
docker run --rm -it -v "$PWD":/work -w /work -p 5173:5173 pyre-dev
# inside the container:
./decompiler-wasm/build.sh
./specs/stage-specs.sh /path/to/Ghidra
cd web && npm install && npm run dev -- --host 0.0.0.0
```

## Layout

```
decompiler-wasm/   C++ → wasm. Vendored Ghidra decompiler tree, multi-region
                   LoadImage, SleighArchitecture subclass, extern "C" bridge,
                   emscripten unity build.
specs/             SLEIGH .sla / .ldefs / .cspec staging + manifest pipeline.
web/               React + Vite + TypeScript + Tailwind frontend, Monaco editor.
docker/            Dev image: emsdk + Node + JDK + gradle.
```

## How it works

```
┌──────────────────── browser ────────────────────┐
│                                                  │
│  React UI ──► Zustand store ──► DecompilerClient │
│                                       │          │
│                         postMessage   ▼          │
│                                ┌─────────────┐   │
│                                │ Web Worker  │   │
│                                │  ┌────────┐ │   │
│                                │  │ wasm   │ │   │
│                                │  │ Ghidra │ │   │
│                                │  │ decomp │ │   │
│                                │  └────────┘ │   │
│                                │  FS lazy-   │   │
│                                │  mount      │   │
│                                │  /spec/...  │   │
│                                └─────────────┘   │
└──────────────────────────────────────────────────┘
```

Three design choices worth flagging:

- **Why a Web Worker (hard requirement)**. Emscripten's `FS.createLazyFile`
  uses *synchronous* XHR on first byte access. That API is illegal on
  the main thread but fine inside a worker. Spec files (~30 MB across
  all architectures Ghidra supports) are mounted as lazy entries; only
  the arch the user actually opens is paid for.
- **Multi-region `LoadImage`**. Mach-O segments live at non-contiguous
  virtual memory addresses, and even ELF binaries can have entry
  points far from the first PT_LOAD page. A flat single-buffer
  projection silently aliases the wrong bytes. Pyre's `WebLoadImage`
  holds an arbitrary set of regions keyed by VMA and zero-fills any
  gaps the decompiler asks about.
- **Lazy libc prototype catalogue**. Ghidra's `parse_C` binds
  prototypes to symbols *by name*, so `printf` / `puts` / `malloc` only
  render as their named forms in decompiled output if the catalogue is
  imported *after* the JS caller has registered the binary's symbols.
  The bridge defers this import to the first `decompile()` call.

## Roadmap

- [ ] `sleighc` build step in `specs/` — compile every `.slaspec`
      under `Ghidra/Processors/` so we ship every architecture Ghidra
      supports out of the box (RISC-V, MIPS, PowerPC, SPARC, ...)
- [ ] In-browser variable rename — round-trip a name edit through the
      worker and re-decompile
- [ ] Persistent workspace (IndexedDB) so refreshing the page doesn't
      drop open tabs
- [ ] Disassembly side panel (Capstone-wasm next to Monaco)
- [ ] WASM module decompilation polish — string / data section parsing,
      better entry-point detection

## License

MIT — see [LICENSE](LICENSE). Vendored Ghidra decompiler sources under
`decompiler-wasm/third_party/` retain their original Apache 2.0 license;
see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for full attribution.
