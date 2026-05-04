// Resolve a Ghidra-emitted callsite identifier to a function address.
//
// Three patterns we recognise, in order of specificity:
//   1. FUN_<hex>          — Ghidra's default name for an un-named function
//   2. func_0x<hex>       — alternative emitted by some PrintC paths
//                           (commonly thunk targets)
//   3. <named-symbol>     — anything in the binary's symbol table
//
// Patterns 1 and 2 carry the address in the name itself, so they
// resolve without consulting the symbol map. Used by:
//   - monaco/linkProvider (cmd+click navigation)
//   - components/XrefsPanel (callees panel)
//   - store/workspace#indexCallers (callers panel index)
//
// Keep these three callers in sync — if you teach this function a new
// pattern, all three benefit automatically.

import type { Hex } from "./types";

export function resolveCall(id: string, nameToAddr: Map<string, Hex>): Hex | null {
  let m = /^FUN_([0-9a-fA-F]+)$/.exec(id);
  if (m) return BigInt("0x" + m[1]);
  m = /^func_0x([0-9a-fA-F]+)$/.exec(id);
  if (m) return BigInt("0x" + m[1]);
  return nameToAddr.get(id) ?? null;
}

// Stateful regex matching every potential callsite identifier in a
// chunk of decompiled C. Returned in source order; iterate with a
// `for..of`. We match ANY identifier followed by `(`; the caller
// is responsible for filtering via resolveCall.
export function* iterCallsites(text: string): Generator<string> {
  const re = /\b([A-Za-z_][A-Za-z0-9_]*)\b(?=\s*\()/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) yield m[1];
}
