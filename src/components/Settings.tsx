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
      <div className="status-loading" role="status" aria-label="Loading settings">
        <div className="spinner" aria-hidden="true" />
      </div>
    );
  }

  return (
    <div className="settings-card">
      <section className="settings-section" aria-labelledby="hd-guard">
        <h2 className="section-label" id="hd-guard">Guard</h2>

        <label className="toggle-row">
          <span className="toggle-label">Enable protection</span>
          <input
            type="checkbox"
            className="toggle"
            role="switch"
            checked={settings.enabled}
            aria-checked={settings.enabled}
            onChange={async (e) => {
              const val = e.target.checked;
              set("enabled", val);
              // Применяем немедленно — не ждём Save
              try { await invoke("cmd_toggle_enabled", { enabled: val }); }
              catch (err) { console.error(err); }
            }}
          />
        </label>

        <label className="toggle-row">
          <span className="toggle-label">Show in menu bar / tray</span>
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

      <section className="settings-section" aria-labelledby="hd-vpn">
        <h2 className="section-label" id="hd-vpn">VPN detection</h2>

        <div className="radio-group" role="radiogroup" aria-labelledby="hd-vpn">
          {([
            ["ip_only",  "IP only — Pepper VPN, Harp (recommended)"],
            ["port",     "Local port — Happ / Xray"],
            ["process",  "Process name"],
          ] as const).map(([val, label]) => (
            <label className="radio-row" key={val}>
              <input
                type="radio"
                name="vpn_mode"
                value={val}
                checked={settings.vpn_mode === val}
                onChange={() => set("vpn_mode", val)}
              />
              <span>{label}</span>
            </label>
          ))}
        </div>

        {settings.vpn_mode === "port" && (
          <div className="field-row">
            <label className="field-label" htmlFor={portId}>Port</label>
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
          <div className="field-row">
            <label className="field-label" htmlFor={processId}>Process</label>
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

      <section className="settings-section" aria-labelledby="hd-interval">
        <h2 className="section-label" id="hd-interval">Check interval</h2>
        <div className="field-row">
          <label className="field-label" htmlFor={intervalId}>Seconds</label>
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
        <p className="field-hint" id="interval-hint">Minimum 10 s · ~1 KB per check</p>
      </section>

      <button
        className={`save-btn ${status === "saved" ? "saved" : ""}`}
        onClick={save}
        disabled={status === "saving"}
        aria-busy={status === "saving"}
      >
        {status === "saving" ? "Saving..." : status === "saved" ? "✓ Saved" : "Save settings"}
      </button>

      <p className="restart-hint" role="note">Tray changes take effect after restart.</p>
    </div>
  );
}
