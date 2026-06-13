import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import StatusCard from "./components/StatusCard";
import Settings from "./components/Settings";
import { GuardStatus } from "./types";
import "./App.css";

type View = "status" | "settings";

const VIEWS: View[] = ["status", "settings"];

export default function App() {
  const [status, setStatus] = useState<GuardStatus | null>(null);
  const [view, setView] = useState<View>("status");
  const [checking, setChecking] = useState(false);
  const [announcement, setAnnouncement] = useState("");
  const prevBlocked = useRef<boolean | null>(null);

  useEffect(() => {
    invoke<GuardStatus>("cmd_get_status").then(setStatus).catch(console.error);

    const unlisten = listen<GuardStatus>("guard:status", ({ payload }) => {
      setStatus(payload);
      if (prevBlocked.current !== null && prevBlocked.current !== payload.blocked) {
        const reasons: Record<string, string> = {
          russian_ip:   "Warning: Russian IP detected. Anthropic traffic blocked.",
          vpn_inactive: "Warning: VPN not active. Anthropic traffic blocked.",
          check_failed: "Warning: IP check failed. Existing firewall rules preserved.",
          initializing: "Claude Guard starting. Traffic blocked until IP verified.",
          none:         "Anthropic traffic restored. Non-Russian IP confirmed.",
        };
        setAnnouncement(reasons[payload.block_reason] ?? "");
      }
      prevBlocked.current = payload.blocked;
    });

    return () => { unlisten.then((f) => f()); };
  }, []);

  const handleCheck = async () => {
    setChecking(true);
    try {
      await invoke("cmd_force_check");
    } finally {
      setTimeout(() => setChecking(false), 1000);
    }
  };

  const handleToggle = async (enabled: boolean) => {
    try {
      await invoke("cmd_toggle_enabled", { enabled });
    } catch (e) {
      console.error(e);
    }
  };

  const handleNavKey = (e: React.KeyboardEvent, current: View) => {
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      setView(current === "status" ? "settings" : "status");
    }
  };

  const blocked = status?.blocked ?? false;

  return (
    <div className={`flex flex-col h-screen w-full bg-[var(--bg)] transition-colors duration-300 ${blocked ? "state-blocked" : "state-safe"}`}>
      <div role="status" aria-live="assertive" aria-atomic="true" className="sr-only">
        {announcement}
      </div>

      <header
        className="flex items-center justify-between pt-[14px] pb-3 px-4 border-b border-[var(--border)] bg-[var(--bg-card)] [-webkit-app-region:drag]"
        role="banner"
      >
        <div className="flex items-center gap-[9px]">
          <div
            className={`status-dot w-2 h-2 rounded-full shrink-0 ${
              blocked
                ? "bg-[var(--red)] shadow-[0_0_6px_var(--red)] animate-pulse-red"
                : status
                ? "bg-[var(--green)] shadow-[0_0_6px_var(--green)]"
                : "bg-[var(--text-dim)]"
            }`}
            role="img"
            aria-label={blocked ? "Blocked" : status ? "Protected" : "Unknown"}
          />
          <span className="text-[13px] font-semibold tracking-[0.3px]">Claude Guard</span>
        </div>

        <nav className="flex gap-1 [-webkit-app-region:no-drag]" role="tablist" aria-label="Main navigation">
          {VIEWS.map((v) => (
            <button
              key={v}
              role="tab"
              id={`tab-${v}`}
              aria-selected={view === v}
              aria-controls={`panel-${v}`}
              className={`px-3 py-1 rounded-md border text-xs cursor-pointer transition-[background,color] duration-150 min-h-7 ${
                view === v
                  ? "bg-[var(--blue-dim)] text-[var(--blue)] font-medium border-[var(--blue-dim)]"
                  : "border-transparent text-[var(--text-muted)] bg-transparent hover:bg-[var(--bg-section)] hover:text-[var(--text)]"
              }`}
              tabIndex={view === v ? 0 : -1}
              onClick={() => setView(v)}
              onKeyDown={(e) => handleNavKey(e, v)}
            >
              {v.charAt(0).toUpperCase() + v.slice(1)}
            </button>
          ))}
        </nav>
      </header>

      <main
        className="flex-1 overflow-y-auto p-4 [scrollbar-width:thin] [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-thumb]:bg-[var(--border)] [&::-webkit-scrollbar-thumb]:rounded-sm"
      >
        <div id="panel-status" role="tabpanel" aria-labelledby="tab-status" hidden={view !== "status"}>
          <StatusCard status={status} checking={checking} onCheck={handleCheck} onToggle={handleToggle} />
        </div>
        <div id="panel-settings" role="tabpanel" aria-labelledby="tab-settings" hidden={view !== "settings"}>
          <Settings />
        </div>
      </main>

      <footer className="px-4 py-2 border-t border-[var(--border)] flex justify-between items-center bg-[var(--bg-card)]" role="contentinfo">
        {status?.last_check && (
          <span className="text-[var(--text-dim)] text-[11px]">
            <span className="sr-only">Last check: </span>
            {status.last_check}
          </span>
        )}
        {status?.error && (
          <span className="text-[var(--yellow)] text-[11px] cursor-help" role="alert" title={status.error}>
            ⚠ Check error
          </span>
        )}
      </footer>
    </div>
  );
}
