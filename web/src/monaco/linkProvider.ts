// Cmd/Ctrl-click navigation. Two halves:
//
// 1. registerNavLinks — Monaco LinkProvider that draws the underline
//    + tooltip affordance over every callsite identifier resolvable
//    to a function address. The URL we write here is opaque; Monaco
//    won't successfully navigate it (custom scheme, browser blocks)
//    but the link still renders.
//
// 2. installClickHandler — per-editor mousedown listener that picks
//    up the actual click and routes it to openTab. Goes around
//    Monaco's link-opener entirely because (a) custom URL schemes
//    don't navigate, and (b) Monaco's resolveLink callback isn't
//    invoked when provideLinks already returned a URL.

import type * as monacoNs from "monaco-editor";
import type { ParsedBinary, Hex } from "@/decompiler/types";
import { resolveCall, iterCallsites } from "@/decompiler/resolveCall";

let providerRegistered = false;
let currentNameToAddr: Map<string, Hex> = new Map();

export function installLinkProvider(
  monaco: typeof monacoNs,
  binary: ParsedBinary,
  _openTab: (addr: Hex) => void,
) {
  // Refresh the lookup map on every binary load so the LinkProvider
  // closure (registered once) sees the new symbol set.
  currentNameToAddr = new Map();
  for (const f of binary.functions) currentNameToAddr.set(f.name, f.addr);

  if (providerRegistered) return;
  providerRegistered = true;

  monaco.languages.registerLinkProvider("pyre-c", {
    provideLinks(model) {
      const links: monacoNs.languages.ILink[] = [];
      const text = model.getValue();
      // iterCallsites yields identifiers in source order; we still
      // need a separate match-index loop to locate them in the text
      // for the link range, so use a regex directly here rather than
      // the iterator helper.
      const re = /\b([A-Za-z_][A-Za-z0-9_]*)\b(?=\s*\()/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const addr = resolveCall(m[1], currentNameToAddr);
        if (addr == null) continue;
        const start = model.getPositionAt(m.index);
        const end = model.getPositionAt(m.index + m[1].length);
        links.push({
          range: {
            startLineNumber: start.lineNumber,
            startColumn: start.column,
            endLineNumber: end.lineNumber,
            endColumn: end.column,
          },
          // Cosmetic only. The mousedown handler below intercepts the
          // click before Monaco's opener runs. We still set a value
          // because some Monaco versions skip the underline affordance
          // for URL-less links.
          url: `pyre://noop/0x${addr.toString(16)}`,
          tooltip: `Open ${m[1]} (0x${addr.toString(16)}) — cmd + click`,
        });
      }
      return { links };
    },
  });
  // Suppress unused-import warning — iterCallsites is exposed by this
  // module's siblings (XrefsPanel, workspace) but not by linkProvider
  // itself, which needs match indices.
  void iterCallsites;
}

// Wire one editor instance up for navigation. Safe to call on every
// MonacoView mount; cleanup runs when the editor disposes.
export function installClickHandler(
  editor: monacoNs.editor.IStandaloneCodeEditor,
  openTab: (addr: Hex) => void,
) {
  // Only Cmd (mac) / Ctrl (win/linux) + left-click navigates. Plain
  // clicks should still let users place the cursor / select text.
  const dom = editor.getDomNode();
  if (!dom) return () => {};

  const onMouseDown = (ev: MouseEvent) => {
    const navKey = ev.metaKey || ev.ctrlKey;
    if (!navKey || ev.button !== 0) return;

    const target = editor.getTargetAtClientPoint(ev.clientX, ev.clientY);
    if (!target?.position) return;
    const model = editor.getModel();
    if (!model) return;
    const word = model.getWordAtPosition(target.position);
    if (!word) return;
    const addr = resolveCall(word.word, currentNameToAddr);
    if (addr == null) return;

    // Prevent Monaco's own link-open from racing us — without this,
    // Brave/Chromium briefly shows an error tab for the pyre://
    // URL on top of our navigation.
    ev.preventDefault();
    ev.stopPropagation();
    openTab(addr);
  };

  // Capture phase so we beat Monaco's bubbling listeners that try to
  // open the link.
  dom.addEventListener("mousedown", onMouseDown, { capture: true });
  return () => dom.removeEventListener("mousedown", onMouseDown, { capture: true });
}
