import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import { useWorkspace } from "@/store/workspace";
import { FileDrop } from "@/components/FileDrop";
import { FunctionList } from "@/components/FunctionList";
import { DecompilerTabs } from "@/components/DecompilerTabs";
import { XrefsPanel } from "@/components/XrefsPanel";
import { StatusBar } from "@/components/StatusBar";

export function App() {
  const status = useWorkspace((s) => s.status);
  const binary = useWorkspace((s) => s.binary);

  // Show the drop zone until a binary is fully ready. The "loading"
  // state still renders FileDrop with a busy indicator so the user
  // sees feedback while the wasm boots + spec mounts complete.
  const showDrop = status !== "ready" || !binary;

  return (
    <div className="h-screen flex flex-col">
      <div className="flex-1 min-h-0">
        {showDrop ? (
          <FileDrop />
        ) : (
          <PanelGroup direction="horizontal">
            <Panel defaultSize={18} minSize={12} maxSize={32}>
              <FunctionList />
            </Panel>
            <PanelResizeHandle className="w-px bg-ink-800" />
            <Panel defaultSize={60} minSize={30}>
              <DecompilerTabs />
            </Panel>
            <PanelResizeHandle className="w-px bg-ink-800" />
            <Panel defaultSize={22} minSize={14} maxSize={36}>
              <XrefsPanel />
            </Panel>
          </PanelGroup>
        )}
      </div>
      <StatusBar />
    </div>
  );
}
