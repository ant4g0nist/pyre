import { useEffect, useRef } from "react";
import Editor, { loader, type OnMount } from "@monaco-editor/react";
import * as monaco from "monaco-editor";
import { useWorkspace } from "@/store/workspace";
import type { OpenTab } from "@/store/workspace";
import { registerPyreC } from "@/monaco/language";
import { installLinkProvider, installClickHandler } from "@/monaco/linkProvider";

// Tell Monaco to use the npm-installed copy instead of fetching from
// jsdelivr at runtime. This makes the dev experience offline-clean
// and gives us deterministic Monaco versioning.
loader.config({ monaco });

let registered = false;

export function MonacoView({ tab }: { tab: OpenTab }) {
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const binary = useWorkspace((s) => s.binary);
  const openTab = useWorkspace((s) => s.openTab);

  // Register the language + theme once per page lifetime — re-running
  // on every mount would noop but logs warnings.
  useEffect(() => {
    if (registered) return;
    registerPyreC(monaco);
    registered = true;
  }, []);

  const onMount: OnMount = (editor) => {
    editorRef.current = editor;
    if (binary) installLinkProvider(monaco, binary, openTab);
    // Per-editor mousedown listener — beats Monaco's built-in
    // link-opener so cmd+click navigates instead of trying to open
    // our placeholder URL. Returns a disposer; tied to the editor's
    // lifetime via onDidDispose so we don't leak listeners across
    // tab switches.
    const dispose = installClickHandler(editor, openTab);
    editor.onDidDispose(dispose);
  };

  // When the tab content changes, update the model. Reusing one editor
  // instance for every tab beats spinning up a fresh Monaco per-tab
  // (Monaco's startup cost is ~80ms a pop).
  useEffect(() => {
    const editor = editorRef.current;
    if (!editor || tab.code == null) return;
    const model = editor.getModel();
    if (model) {
      // setValue keeps the editor scrolled to the top — better UX
      // than preserving the previous tab's scroll position.
      model.setValue(tab.code);
    }
  }, [tab.code]);

  if (tab.error) {
    return (
      <div className="p-4 font-mono text-sm text-red-400 whitespace-pre-wrap">
        {tab.error}
      </div>
    );
  }
  if (tab.loading) {
    return (
      <div className="p-4 font-mono text-sm text-ink-400 animate-pulse">
        Decompiling {tab.name}…
      </div>
    );
  }

  return (
    <Editor
      height="100%"
      defaultLanguage="pyre-c"
      language="pyre-c"
      value={tab.code ?? ""}
      onMount={onMount}
      theme="pyre-dark"
      options={{
        readOnly: true,
        fontSize: 13,
        fontFamily: "'JetBrains Mono', 'SF Mono', Menlo, monospace",
        lineNumbers: "on",
        renderLineHighlight: "line",
        scrollBeyondLastLine: false,
        smoothScrolling: true,
        cursorBlinking: "smooth",
        renderWhitespace: "none",
        wordWrap: "off",
        folding: true,
        guides: { indentation: true },
        minimap: { enabled: false },
        padding: { top: 12 },
      }}
    />
  );
}
