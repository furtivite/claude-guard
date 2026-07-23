import { useState, useEffect, useId } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Settings as SettingsType } from "../types";

const DEFAULTS: SettingsType = {
  enabled: true,
  check_interval: 30,
  show_tray: true,
  vpn_mode: "ip_only",
  vpn_port: 10808,
  vpn_process: "",
};

export default function Settings() {
  const [settings, setSettings] = useState<SettingsType>(DEFAULTS);
  const [status, setStatus] = useState<"idle" | "saving" | "saved">("idle");
  const [loading, setLoading] = useState(true);

  const portId = useId();
  const processId = useId();
  const intervalId = useId();

  useEffect(() => {
    invoke<SettingsType>("cmd_get_settings")
      .then(setSettings)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const save = async () => {
    setStatus("saving");
    try {
      await invoke("cmd_save_settings", { settings });
      setStatus("saved");
      setTimeout(() => setStatus("idle"), 2000);
    } catch (e) {
      console.error(e);
      setStatus("idle");
    }
  };

  const set = <K extends keyof SettingsType>(key: K, val: SettingsType[K]) =>
    setSettings((s) => ({ ...s, [key]: val }));

  if (loading) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-3 h-[200px] text-[var(--text-muted)]"
        role="status"
        aria-label="Loading settings"
      >
        <div
          className="w-[22px] h-[22px] border-2 border-[var(--border)] border-t-[var(--blue)] rounded-full animate-spin"
          aria-hidden="true"
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <section
        className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl py-3 px-[14px] flex flex-col gap-2"
        aria-labelledby="hd-guard"
      >
        <h2
          className="text-[10px] font-semibold uppercase tracking-[0.8px] text-[var(--text-dim)]"
          id="hd-guard"
        >
          Guard
        </h2>

        <label className="flex justify-between items-center py-1 gap-3">
          <span className="text-[13px] cursor-pointer">Enable protection</span>
          <input
            type="checkbox"
            className="toggle"
            role="switch"
            checked={settings.enabled}
            aria-checked={settings.enabled}
            onChange={async (e) => {
              const val = e.target.checked;
              set("enabled", val);
              try {
                await invoke("cmd_toggle_enabled", { enabled: val });
              } catch (err) {
                console.error(err);
              }
            }}
          />
        </label>

        <label className="flex justify-between items-center py-1 gap-3">
          <span className="text-[13px] cursor-pointer">Show in menu bar / tray</span>
          <input
            type="checkbox"
            className="toggle"
            role="switch"
            checked={settings.show_tray}
            aria-checked={settings.show_tray}
            onChange={(e) => set("show_tray", e.target.checked)}
          />
        </label>
      </section>

      <section
        className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl py-3 px-[14px] flex flex-col gap-2"
        aria-labelledby="hd-vpn"
      >
        <h2
          className="text-[10px] font-semibold uppercase tracking-[0.8px] text-[var(--text-dim)]"
          id="hd-vpn"
        >
          VPN detection
        </h2>

        <div className="flex flex-col gap-[6px]" role="radiogroup" aria-labelledby="hd-vpn">
          {(
            [
              ["ip_only", "IP only — Pepper VPN, Harp (recommended)"],
              ["port", "Local port — Happ / Xray"],
              ["process", "Process name"],
            ] as const
          ).map(([val, label]) => (
            <label className="flex items-center gap-2 cursor-pointer text-xs min-h-6" key={val}>
              <input
                type="radio"
                name="vpn_mode"
                value={val}
                checked={settings.vpn_mode === val}
                onChange={() => set("vpn_mode", val)}
                className="accent-[var(--blue)] w-[14px] h-[14px] cursor-pointer"
              />
              <span>{label}</span>
            </label>
          ))}
        </div>

        {settings.vpn_mode === "port" && (
          <div className="flex items-center gap-[10px] mt-1">
            <label className="text-xs text-[var(--text-muted)] min-w-[80px]" htmlFor={portId}>
              Port
            </label>
            <input
              id={portId}
              type="number"
              className="field-input"
              value={settings.vpn_port}
              min={1}
              max={65535}
              onChange={(e) => set("vpn_port", Number(e.target.value))}
            />
          </div>
        )}

        {settings.vpn_mode === "process" && (
          <div className="flex items-center gap-[10px] mt-1">
            <label className="text-xs text-[var(--text-muted)] min-w-[80px]" htmlFor={processId}>
              Process
            </label>
            <input
              id={processId}
              type="text"
              className="field-input mono"
              value={settings.vpn_process}
              placeholder="e.g. Tunnel"
              onChange={(e) => set("vpn_process", e.target.value)}
            />
          </div>
        )}
      </section>

      <section
        className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl py-3 px-[14px] flex flex-col gap-2"
        aria-labelledby="hd-interval"
      >
        <h2
          className="text-[10px] font-semibold uppercase tracking-[0.8px] text-[var(--text-dim)]"
          id="hd-interval"
        >
          Check interval
        </h2>
        <div className="flex items-center gap-[10px] mt-1">
          <label className="text-xs text-[var(--text-muted)] min-w-[80px]" htmlFor={intervalId}>
            Seconds
          </label>
          <input
            id={intervalId}
            type="number"
            className="field-input"
            value={settings.check_interval}
            min={10}
            max={300}
            step={5}
            aria-describedby="interval-hint"
            onChange={(e) => set("check_interval", Number(e.target.value))}
          />
        </div>
        <p className="text-[11px] text-[var(--text-dim)]" id="interval-hint">
          Minimum 10 s · ~1 KB per check
        </p>
      </section>

      <button
        className={`w-full py-[10px] min-h-9 rounded-[7px] border-none text-[13px] font-semibold cursor-pointer transition-colors duration-150 text-white hover:brightness-110 disabled:opacity-60 disabled:cursor-not-allowed ${
          status === "saved" ? "bg-[var(--green)]" : "bg-[var(--blue)]"
        }`}
        onClick={save}
        disabled={status === "saving"}
        aria-busy={status === "saving"}
      >
        {status === "saving" ? "Saving..." : status === "saved" ? "✓ Saved" : "Save settings"}
      </button>

      <p className="text-[11px] text-[var(--text-dim)] text-center" role="note">
        Tray changes take effect after restart.
      </p>
    </div>
  );
}
