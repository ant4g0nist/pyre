import { useWorkspace } from "@/store/workspace";

export function StatusBar() {
  const binary = useWorkspace((s) => s.binary);
  const fileName = useWorkspace((s) => s.fileName);
  const tabs = useWorkspace((s) => s.tabs);
  const focused = useWorkspace((s) => s.focusedAddr);
  const reset = useWorkspace((s) => s.reset);

  const focusedTab = tabs.find((t) => t.addr === focused);

  return (
    <div className="h-7 px-3 bg-ink-900 border-t border-ink-800 flex items-center text-xs text-ink-400 gap-3 select-none">
      <span className="text-accent-fg font-semibold">⌬ Pyre</span>
      <span className="text-ink-700">·</span>
      {binary ? (
        <>
          <span className="font-mono truncate max-w-[20ch]" title={fileName ?? ""}>
            {fileName}
          </span>
          <span className="text-ink-700">·</span>
          <span className="uppercase">{binary.format}</span>
          <span className="text-ink-700">·</span>
          <span>{binary.languageId}</span>
          <span className="text-ink-700">·</span>
          <span>{binary.functions.length} functions</span>
          <span className="ml-auto" />
          {focusedTab?.ms != null && (
            <span className="text-ink-500">
              {focusedTab.name} decompiled in {focusedTab.ms}ms
            </span>
          )}
          <button
            onClick={reset}
            className="px-2 py-0.5 ml-2 rounded text-ink-400 hover:text-white hover:bg-ink-800"
            title="Close binary and load a different one"
          >
            close
          </button>
        </>
      ) : (
        <span className="text-ink-500">no binary loaded</span>
      )}
    </div>
  );
}
