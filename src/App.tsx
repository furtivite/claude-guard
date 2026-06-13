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
    <div className={`app ${blocked ? "state-blocked" : "state-safe"}`}>
      {/* Объявления для скринридера */}
      <div role="status" aria-live="assertive" aria-atomic="true" className="sr-only">
        {announcement}
      </div>

      <header className="app-header" role="banner">
        <div className="header-left">
          <div
            className={`status-dot ${blocked ? "dot-blocked" : status ? "dot-safe" : "dot-unknown"}`}
            role="img"
            aria-label={blocked ? "Blocked" : status ? "Protected" : "Unknown"}
          />
          <span className="app-title">Claude Guard</span>
        </div>

        <nav className="header-nav" role="tablist" aria-label="Main navigation">
          {VIEWS.map((v) => (
            <button
              key={v}
              role="tab"
              id={`tab-${v}`}
              aria-selected={view === v}
              aria-controls={`panel-${v}`}
              className={`nav-btn ${view === v ? "active" : ""}`}
              tabIndex={view === v ? 0 : -1}
              onClick={() => setView(v)}
              onKeyDown={(e) => handleNavKey(e, v)}
            >
              {v.charAt(0).toUpperCase() + v.slice(1)}
            </button>
          ))}
        </nav>
      </header>

      <main className="app-content">
        <div id="panel-status" role="tabpanel" aria-labelledby="tab-status" hidden={view !== "status"}>
          <StatusCard status={status} checking={checking} onCheck={handleCheck} onToggle={handleToggle} />
        </div>
        <div id="panel-settings" role="tabpanel" aria-labelledby="tab-settings" hidden={view !== "settings"}>
          <Settings />
        </div>
      </main>

      <footer className="app-footer" role="contentinfo">
        {status?.last_check && (
          <span className="last-check">
            <span className="sr-only">Last check: </span>
            {status.last_check}
          </span>
        )}
        {status?.error && (
          <span className="error-hint" role="alert" title={status.error}>
            ⚠ Check error
          </span>
        )}
      </footer>
    </div>
  );
}
