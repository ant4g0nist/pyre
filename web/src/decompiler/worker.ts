// Web Worker that owns the pyre decompiler module.
//
// Why a worker (hard requirement, not just a perf win): emscripten's
// FS.createLazyFile uses *synchronous* XHR on first byte access. That
// API is illegal on the main thread but fine inside a worker. Trying
// to drive the decompiler from the main thread would either deadlock
// or force us to pre-fetch every spec file up-front (~30MB just for
// x86 + AARCH64 + ARM + MIPS).
//
// Spec lazy-mounting strategy: the worker registers FS lazy entries
// for one architecture's slice of the manifest and calls
// pyre_add_spec_dir for each .../data/languages directory.
// Subsequent init() calls with a different `arch` mount additional
// processors without re-fetching anything that's already mounted.

/// <reference lib="webworker" />

import type {
  WorkerRequest,
  WorkerReply,
  InitRequest,
  OpenRequest,
  DecompileRequest,
  CloseRequest,
  Hex,
} from "./types";

// The emscripten ES module loader. Symlinked into src/ alongside this
// file (../decompiler-wasm/dist/pyre_decompiler.js) so vite treats
// it as a module — files under /public/ can only be referenced via
// <script src>, not imported. The companion .wasm stays in /public/
// and emscripten fetches it at runtime via the locateFile callback
// passed at construction time.
// @ts-expect-error — emitted by emscripten, no .d.ts shipped
import PyreDecompiler from "./pyre_decompiler.js";

interface EmModule {
  FS: {
    mkdir(path: string): void;
    createLazyFile(
      parent: string,
      name: string,
      url: string,
      canRead: boolean,
      canWrite: boolean,
    ): void;
  };
  ccall: (...args: unknown[]) => unknown;
  cwrap: (
    name: string,
    ret: string | null,
    args: (string | null)[],
  ) => (...args: unknown[]) => unknown;
  HEAPU8: Uint8Array;
  UTF8ToString: (ptr: number) => string;
  _malloc: (n: number) => number;
  _free: (ptr: number) => void;
}

interface DecompilerApi {
  init: (specRoot: string) => number;
  add_spec_dir: (dir: string) => number;
  create: (languageId: string) => number;
  add_region: (
    handle: number,
    addr: bigint,
    bytes: number,
    size: number,
  ) => number;
  add_symbol: (handle: number, addr: bigint, name: string) => number;
  add_string: (handle: number, addr: bigint, len: bigint) => number;
  add_readonly: (handle: number, addr: bigint, size: bigint) => number;
  decompile: (handle: number, addr: bigint, name: string) => number;
  free_string: (ptr: number) => void;
  destroy: (handle: number) => void;
}

let mod: EmModule | null = null;
let api: DecompilerApi | null = null;
const sessions = new Map<number, number>(); // sessionId → wasm handle ptr
let nextSession = 1;
let cachedManifest: { files: { path: string; size: number }[] } | null = null;
const mountedArchs = new Set<string>();

function bindApi(m: EmModule): DecompilerApi {
  return {
    init: m.cwrap("pyre_init", "number", ["string"]) as DecompilerApi["init"],
    add_spec_dir: m.cwrap("pyre_add_spec_dir", "number", [
      "string",
    ]) as DecompilerApi["add_spec_dir"],
    create: m.cwrap("pyre_create", "number", ["string"]) as DecompilerApi["create"],
    add_region: m.cwrap("pyre_add_region", "number", [
      "number",
      "bigint",
      "number",
      "number",
    ]) as DecompilerApi["add_region"],
    add_symbol: m.cwrap("pyre_add_symbol", "number", [
      "number",
      "bigint",
      "string",
    ]) as DecompilerApi["add_symbol"],
    add_string: m.cwrap("pyre_add_string", "number", [
      "number",
      "bigint",
      "bigint",
    ]) as DecompilerApi["add_string"],
    add_readonly: m.cwrap("pyre_add_readonly", "number", [
      "number",
      "bigint",
      "bigint",
    ]) as DecompilerApi["add_readonly"],
    decompile: m.cwrap("pyre_decompile", "number", [
      "number",
      "bigint",
      "string",
    ]) as DecompilerApi["decompile"],
    free_string: m.cwrap("pyre_free_string", null, [
      "number",
    ]) as DecompilerApi["free_string"],
    destroy: m.cwrap("pyre_destroy", null, ["number"]) as DecompilerApi["destroy"],
  };
}

// Walk a relative path like "x86/data/languages/x86-64.sla", create
// missing dirs under /spec/, and register a lazy file pointing at the
// CDN/static URL. emscripten fetches bytes synchronously on first
// access (worker-safe).
function mountLazyFile(FS: EmModule["FS"], relPath: string, url: string) {
  const parts = relPath.split("/");
  let cur = "/spec";
  for (let i = 0; i < parts.length - 1; i++) {
    cur += "/" + parts[i];
    try {
      FS.mkdir(cur);
    } catch {
      /* EEXIST — fine */
    }
  }
  FS.createLazyFile(cur, parts[parts.length - 1], url, true, false);
}

async function doInit(req: InitRequest) {
  if (!mod) {
    // locateFile redirects emscripten's relative-to-loader fetch (which
    // would land at /src/decompiler/pyre_decompiler.wasm and 404)
    // back at the public-served binary. import.meta.env.BASE_URL is
    // injected by vite — `/` in dev, `/<repo>/` for GH Pages project
    // pages — and ALWAYS ends with a slash, so concatenation is safe.
    const base = import.meta.env.BASE_URL;
    mod = (await PyreDecompiler({
      locateFile: (path: string) => `${base}decompiler/${path}`,
    })) as EmModule;
    api = bindApi(mod);
    try {
      mod.FS.mkdir("/spec");
    } catch {
      /* fine */
    }
  }
  if (mountedArchs.has(req.arch)) return;
  mountedArchs.add(req.arch);

  if (!cachedManifest) {
    const r = await fetch(req.manifestUrl);
    if (!r.ok) throw new Error(`fetch manifest ${req.manifestUrl}: ${r.status}`);
    cachedManifest = await r.json();
  }

  // Mount only this arch's slice. SleighArchitecture scans every
  // registered spec dir at handle-create time; mounting the entire
  // manifest would pull every architecture's .ldefs even when the
  // user only ever decompiles AArch64.
  const archPrefix = req.arch + "/";
  const langDirs = new Set<string>();
  for (const entry of cachedManifest!.files) {
    if (!entry.path.startsWith(archPrefix)) continue;
    mountLazyFile(mod!.FS, entry.path, req.specBaseUrl + entry.path);
    const parts = entry.path.split("/");
    if (parts[parts.length - 2] === "languages") {
      langDirs.add("/spec/" + parts.slice(0, -1).join("/"));
    }
  }
  for (const dir of langDirs) {
    if (api!.add_spec_dir(dir) !== 0) {
      throw new Error(`add_spec_dir(${dir}) failed`);
    }
  }
}

function doOpen(req: OpenRequest): number {
  if (!mod || !api) throw new Error("worker not initialized");
  if (req.regions.length === 0)
    throw new Error("open requires at least one region");

  const handle = api.create(req.languageId);
  if (!handle) throw new Error(`decompiler create failed for ${req.languageId}`);

  // Stage each region into the wasm heap one at a time. The bridge
  // copies into a C++-owned vector, so peak memory is bounded by the
  // largest single region (typical 64-bit ELF .text < 10MB).
  for (const region of req.regions) {
    const u8 =
      region.bytes instanceof Uint8Array
        ? region.bytes
        : new Uint8Array(region.bytes);
    if (u8.length === 0) continue;
    const ptr = mod._malloc(u8.length);
    mod.HEAPU8.set(u8, ptr);
    api.add_region(handle, region.vaddr, ptr, u8.length);
    mod._free(ptr);
  }
  for (const [addr, name] of req.symbols) api.add_symbol(handle, addr, name);
  for (const [addr, size] of req.readonly) api.add_readonly(handle, addr, size);
  for (const [addr, len] of req.strings)
    api.add_string(handle, addr, BigInt(len));

  const id = nextSession++;
  sessions.set(id, handle);
  return id;
}

function doDecompile(req: DecompileRequest): string {
  if (!mod || !api) throw new Error("worker not initialized");
  const handle = sessions.get(req.sessionId);
  if (!handle) throw new Error(`unknown session ${req.sessionId}`);
  const cstr = api.decompile(handle, req.address, req.name ?? "");
  if (!cstr) throw new Error("decompile returned null");
  const code = mod.UTF8ToString(cstr);
  api.free_string(cstr);
  return code;
}

function doClose(req: CloseRequest) {
  if (!api) return;
  const handle = sessions.get(req.sessionId);
  if (handle != null) {
    api.destroy(handle);
    sessions.delete(req.sessionId);
  }
}

self.addEventListener("message", async (ev: MessageEvent<WorkerRequest>) => {
  const req = ev.data;
  try {
    let reply: WorkerReply;
    switch (req.cmd) {
      case "init":
        await doInit(req);
        reply = { id: req.id, ok: true };
        break;
      case "open":
        reply = { id: req.id, ok: true, sessionId: doOpen(req) };
        break;
      case "decompile":
        reply = { id: req.id, ok: true, code: doDecompile(req) };
        break;
      case "close":
        doClose(req);
        reply = { id: req.id, ok: true };
        break;
      default:
        // exhaustiveness check — leave unreachable so TS catches new
        // command additions
        reply = { id: (req as { id: number }).id, ok: false, error: "unknown cmd" };
    }
    (self as unknown as Worker).postMessage(reply);
  } catch (err) {
    (self as unknown as Worker).postMessage({
      id: req.id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    } satisfies WorkerReply);
  }
});

// Marker so vite knows this is a real module (not just types).
export type { Hex };
