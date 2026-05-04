# Third-party notices

Pyre bundles or depends on the components below. Each retains its
original license. The Pyre-original code (the emscripten bridge, the
SLEIGH spec staging script, the React frontend, the build scripts) is
MIT-licensed; see [LICENSE](LICENSE).

## Ghidra decompiler (Apache License 2.0)

`decompiler-wasm/third_party/ghidra-decompiler/` contains C++ source
from the National Security Agency's Ghidra Software Reverse
Engineering Framework, with patches for standalone (non-Java) compilation
originally developed by the [r2ghidra](https://github.com/radareorg/r2ghidra)
project.

- Project: https://github.com/NationalSecurityAgency/ghidra
- License: Apache License, Version 2.0
- License text: https://www.apache.org/licenses/LICENSE-2.0

## SLEIGH processor specifications (Apache License 2.0)

The compiled `.sla` / `.ldefs` / `.cspec` / `.pspec` files served by
`specs/dist/` are derived from the same Ghidra distribution and carry
the same Apache 2.0 license.

## Emscripten (MIT / University of Illinois NCSA)

The wasm module is compiled with the [Emscripten](https://emscripten.org)
toolchain. Emscripten is a build-time dependency only; no Emscripten
source is redistributed in this repository.

## NPM dependencies

The web frontend depends on React, Monaco Editor, Tailwind CSS,
Zustand, react-resizable-panels, @tanstack/react-virtual, Vite, and
TypeScript. Each is permissively licensed (MIT / Apache 2.0 / BSD).
See `web/package.json` and the corresponding upstream repositories
for full license text.
