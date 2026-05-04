import { useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useWorkspace } from "@/store/workspace";

export function FunctionList() {
  const binary = useWorkspace((s) => s.binary);
  const focused = useWorkspace((s) => s.focusedAddr);
  const openTab = useWorkspace((s) => s.openTab);
  const [filter, setFilter] = useState("");
  const parentRef = useRef<HTMLDivElement | null>(null);

  const items = useMemo(() => {
    if (!binary) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return binary.functions;
    // Cheap fuzzy: substring on name OR address. Sort name-prefix
    // matches first so typing "ma" puts `main` above
    // `__libc_start_main`.
    return binary.functions
      .filter(
        (f) =>
          f.name.toLowerCase().includes(q) ||
          f.addr.toString(16).includes(q),
      )
      .sort((a, b) => {
        const ap = a.name.toLowerCase().startsWith(q) ? 0 : 1;
        const bp = b.name.toLowerCase().startsWith(q) ? 0 : 1;
        if (ap !== bp) return ap - bp;
        return a.name.localeCompare(b.name);
      });
  }, [binary, filter]);

  const virtual = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 12,
  });

  return (
    <div className="flex h-full flex-col bg-ink-900 border-r border-ink-800">
      <div className="p-2 border-b border-ink-800">
        <input
          className="w-full px-2 py-1.5 text-sm bg-ink-850 border border-ink-700 rounded focus:outline-none focus:border-accent placeholder:text-ink-500"
          placeholder="Search functions…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <div className="mt-1 text-xs text-ink-500">
          {items.length} of {binary?.functions.length ?? 0}
        </div>
      </div>
      <div ref={parentRef} className="flex-1 overflow-auto">
        <div
          style={{
            height: virtual.getTotalSize(),
            position: "relative",
          }}
        >
          {virtual.getVirtualItems().map((vi) => {
            const f = items[vi.index];
            const isFocused = focused === f.addr;
            return (
              <button
                key={f.addr.toString()}
                onClick={() => openTab(f.addr)}
                className={[
                  "absolute inset-x-0 px-3 text-left text-xs font-mono",
                  "flex items-center gap-2 truncate",
                  "hover:bg-ink-800 transition-colors",
                  isFocused ? "bg-accent/20 text-white" : "text-ink-300",
                ].join(" ")}
                style={{
                  top: vi.start,
                  height: vi.size,
                }}
                title={`${f.name}  ·  0x${f.addr.toString(16)}${
                  f.size ? `  ·  ${f.size} bytes` : ""
                }`}
              >
                <span className="text-ink-500 shrink-0">
                  {f.addr.toString(16).padStart(8, "0").slice(-8)}
                </span>
                <span className="truncate">{f.name}</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
