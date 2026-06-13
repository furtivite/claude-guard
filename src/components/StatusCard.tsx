import { invoke } from "@tauri-apps/api/core";
import { GuardStatus, BlockReason } from "../types";

interface Props {
  status: GuardStatus | null;
  checking: boolean;
  onCheck: () => void;
  onToggle: (enabled: boolean) => void;
}

function countryCodeToEmoji(code: string): string {
  return [...code.toUpperCase()]
    .map((c) => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join("");
}

// Человекочитаемое описание причины блокировки
function blockReasonLabel(reason: BlockReason): string {
  switch (reason) {
    case "russian_ip":   return "Russian IP detected";
    case "vpn_inactive": return "VPN not active";
    case "check_failed": return "IP check unavailable — rules preserved";
    case "initializing": return "Starting up, checking IP…";
    case "none":         return "Non-Russian IP confirmed";
  }
}

function blockReasonAriaLabel(reason: BlockReason, blocked: boolean): string {
  if (!blocked) return "Anthropic traffic allowed — " + blockReasonLabel(reason);
  return "Anthropic traffic blocked — " + blockReasonLabel(reason);
}

export default function StatusCard({ status, checking, onCheck, onToggle }: Props) {
  if (!status) {
    return (
      <div className="status-loading" role="status" aria-label="Loading">
        <div className="spinner" aria-hidden="true" />
        <span>Initializing...</span>
      </div>
    );
  }

  const { blocked, block_reason, ip_info, vpn_interface, vpn_active, guard_enabled } = status;

  // check_failed — особый случай: заблокировано но не из-за RU IP
  const isUncertain = block_reason === "check_failed" || block_reason === "initializing";

  return (
    <div className="status-card">
      <div
        className={`block-indicator ${blocked ? (isUncertain ? "uncertain" : "blocked") : "safe"}`}
        role="region"
        aria-label={
          !guard_enabled
            ? "Guard disabled — enable in Settings"
            : blockReasonAriaLabel(block_reason, blocked)
        }
      >
        <span className="indicator-icon" aria-hidden="true">
          {!guard_enabled ? "⚪" : blocked ? (isUncertain ? "🟡" : "🔴") : "🟢"}
        </span>
        <div>
          <div className="indicator-title">
            {!guard_enabled
              ? "Guard disabled"
              : blocked
              ? "Anthropic BLOCKED"
              : "Anthropic allowed"}
          </div>
          <div className="indicator-sub">
            {!guard_enabled ? "Enable in Settings" : blockReasonLabel(block_reason)}
          </div>
        </div>
      </div>

      <section className="info-section" aria-label="IP information">
        <h2 className="section-label">Your IP</h2>
        <dl>
          <div className="info-row">
            <dt className="info-key">Address</dt>
            <dd className="info-val mono">{ip_info?.ip ?? "—"}</dd>
          </div>
          <div className="info-row">
            <dt className="info-key">Country</dt>
            <dd className="info-val country-val">
              {ip_info?.country_code && (
                <span className="flag-emoji" aria-hidden="true">
                  {countryCodeToEmoji(ip_info.country_code)}
                </span>
              )}
              {ip_info?.country ?? "—"}
            </dd>
          </div>
          <div className="info-row">
            <dt className="info-key">City</dt>
            <dd className="info-val">
              {ip_info ? [ip_info.city, ip_info.region].filter(Boolean).join(", ") : "—"}
            </dd>
          </div>
          <div className="info-row">
            <dt className="info-key">Provider</dt>
            <dd className="info-val mono small" title={ip_info?.org}>{ip_info?.org ?? "—"}</dd>
          </div>
        </dl>
      </section>

      <section className="info-section" aria-label="VPN status">
        <h2 className="section-label">VPN</h2>
        <dl>
          <div className="info-row">
            <dt className="info-key">Interface</dt>
            <dd className={`info-val ${vpn_interface ? "vpn-active" : "vpn-none"}`}>
              {vpn_interface ?? "Not detected"}
            </dd>
          </div>
          <div className="info-row">
            <dt className="info-key">State</dt>
            <dd className={`info-val ${vpn_active ? "vpn-active" : "vpn-none"}`}>
              {vpn_active ? "Active" : "Inactive"}
            </dd>
          </div>
        </dl>
      </section>

      <div className="action-row">
        <button
          className={`toggle-guard-btn ${guard_enabled ? "active" : "inactive"}`}
          onClick={() => onToggle(!guard_enabled)}
          aria-label={guard_enabled ? "Disable protection" : "Enable protection"}
          aria-pressed={guard_enabled}
        >
          {guard_enabled ? "Disable" : "Enable protection"}
        </button>

        <button
          className={`check-btn ${checking ? "checking" : ""}`}
          onClick={onCheck}
          disabled={checking || !guard_enabled}
          aria-label={checking ? "Checking IP, please wait" : "Check IP now"}
          aria-busy={checking}
        >
          {checking
            ? <><span className="spinner-sm" aria-hidden="true" /> Checking...</>
            : "Check now"}
        </button>
      </div>
    </div>
  );
}
