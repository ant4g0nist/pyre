import { useMemo } from "react";
import { useWorkspace } from "@/store/workspace";
import type { Hex } from "@/decompiler/types";
import { resolveCall, iterCallsites } from "@/decompiler/resolveCall";

export function XrefsPanel() {
  const binary = useWorkspace((s) => s.binary);
  const focused = useWorkspace((s) => s.focusedAddr);
  const tabs = useWorkspace((s) => s.tabs);
  const xrefsTo = useWorkspace((s) => s.xrefsTo);
  const openTab = useWorkspace((s) => s.openTab);

  const focusedTab = tabs.find((t) => t.addr === focused);

  // Callees: walk every callsite identifier in the focused tab's
  // decompiled C, route through resolveCall so synthetic FUN_<hex>
  // and func_0x<hex> names work alongside real symbols, then dedupe
  // by address.
  const callees = useMemo<{ addr: Hex; name: string }[]>(() => {
    if (!binary || !focusedTab?.code) return [];
    const nameToAddr = new Map<string, Hex>();
    const addrToName = new Map<string, string>();
    for (const f of binary.functions) {
      nameToAddr.set(f.name, f.addr);
      addrToName.set(f.addr.toString(), f.name);
    }
    const out: { addr: Hex; name: string }[] = [];
    const seen = new Set<string>();
    for (const id of iterCallsites(focusedTab.code)) {
      const addr = resolveCall(id, nameToAddr);
      if (addr == null || addr === focused) continue;
      const key = addr.toString();
      if (seen.has(key)) continue;
      seen.add(key);
      // Prefer the binary's known symbol over the synthetic FUN_/func_
      // form so callees show up under their real name when available.
      out.push({ addr, name: addrToName.get(key) ?? id });
    }
    return out;
  }, [binary, focusedTab?.code, focused]);

  const callers = useMemo<{ addr: Hex; name: string }[]>(() => {
    if (!binary || focused == null) return [];
    const list = xrefsTo.get(focused.toString()) ?? [];
    const addrToName = new Map<string, string>();
    for (const f of binary.functions) addrToName.set(f.addr.toString(), f.name);
    return list.map((a) => ({
      addr: a,
      name: addrToName.get(a.toString()) ?? `FUN_${a.toString(16)}`,
    }));
  }, [binary, focused, xrefsTo]);

  if (!focusedTab) {
    return (
      <div className="h-full bg-ink-900 border-l border-ink-800 p-3 text-xs text-ink-500">
        No function selected.
      </div>
    );
  }

  return (
    <div className="h-full bg-ink-900 border-l border-ink-800 flex flex-col">
      <div className="px-3 py-2 border-b border-ink-800">
        <div className="text-xs uppercase tracking-wide text-ink-500">
          Cross-references
        </div>
        <div className="text-sm font-mono text-white truncate">
          {focusedTab.name}
        </div>
      </div>
      <div className="flex-1 overflow-auto">
        <Section
          title="Callers (To)"
          empty="No callers indexed yet — open more functions to grow the index."
          items={callers}
          onClick={openTab}
        />
        <Section
          title="Callees (From)"
          empty="No outgoing calls."
          items={callees}
          onClick={openTab}
        />
      </div>
    </div>
  );
}

function Section({
  title,
  items,
  empty,
  onClick,
}: {
  title: string;
  items: { addr: Hex; name: string }[];
  empty: string;
  onClick: (a: Hex) => void;
}) {
  return (
    <div className="border-b border-ink-800">
      <div className="px-3 py-1.5 text-xs uppercase tracking-wide text-ink-500 bg-ink-850">
        {title} {items.length > 0 && <span className="opacity-60">({items.length})</span>}
      </div>
      {items.length === 0 ? (
        <div className="px-3 py-2 text-xs text-ink-500">{empty}</div>
      ) : (
        <ul>
          {items.map((it) => (
            <li key={it.addr.toString() + it.name}>
              <button
                className="w-full text-left px-3 py-1 font-mono text-xs flex items-center gap-2 hover:bg-ink-800 transition-colors"
                onClick={() => onClick(it.addr)}
                title={`0x${it.addr.toString(16)}`}
              >
                <span className="text-ink-500 shrink-0">
                  {it.addr.toString(16).slice(-8)}
                </span>
                <span className="truncate text-ink-200">{it.name}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
