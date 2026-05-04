import { useCallback, useRef, useState } from "react";
import { useWorkspace } from "@/store/workspace";

export function FileDrop() {
  const loadFile = useWorkspace((s) => s.loadFile);
  const status = useWorkspace((s) => s.status);
  const errorMessage = useWorkspace((s) => s.errorMessage);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const handleFiles = useCallback(
    async (files: FileList | File[] | null) => {
      if (!files || files.length === 0) return;
      const file = files instanceof FileList ? files[0] : files[0];
      await loadFile(file);
    },
    [loadFile],
  );

  return (
    <div
      className={[
        "flex h-full w-full items-center justify-center p-8 transition-colors",
        dragOver ? "bg-accent/10" : "bg-ink-950",
      ].join(" ")}
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragOver(false);
        handleFiles(e.dataTransfer.files);
      }}
    >
      <div
        className={[
          "max-w-md w-full rounded-2xl border-2 border-dashed p-12 text-center",
          "border-ink-700 hover:border-accent transition-colors",
        ].join(" ")}
      >
        <div className="text-6xl mb-3 select-none">⌬</div>
        <h1 className="text-2xl font-semibold tracking-tight">Pyre</h1>
        <p className="text-ink-400 text-sm mt-1">
          Ghidra decompiler in your browser.
        </p>
        <p className="text-ink-500 text-xs mt-6">
          Drop an ELF, Mach-O, PE, or .wasm here
        </p>
        <button
          className="mt-3 px-4 py-2 rounded-lg bg-accent text-white font-medium hover:bg-accent-fg transition-colors"
          onClick={() => inputRef.current?.click()}
        >
          or pick a file
        </button>
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => handleFiles(e.target.files)}
        />
        {status === "loading" && (
          <p className="mt-6 text-accent-fg text-sm animate-pulse">
            Loading + initializing decompiler…
          </p>
        )}
        {status === "error" && errorMessage && (
          <p className="mt-6 text-red-400 text-sm font-mono">{errorMessage}</p>
        )}
      </div>
    </div>
  );
}
