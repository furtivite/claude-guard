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

function blockReasonLabel(reason: BlockReason): string {
  switch (reason) {
    case "russian_ip":
      return "Russian IP detected";
    case "vpn_inactive":
      return "VPN not active";
    case "check_failed":
      return "IP check unavailable — rules preserved";
    case "initializing":
      return "Starting up, checking IP…";
    case "none":
      return "Non-Russian IP confirmed";
    case "firewall_error":
      return "Firewall command failed";
  }
}

function blockReasonAriaLabel(reason: BlockReason, blocked: boolean): string {
  if (reason === "firewall_error" && !blocked) {
    return "Warning: Anthropic traffic is NOT blocked — the firewall rules could not be applied";
  }
  if (!blocked) return "Anthropic traffic allowed — " + blockReasonLabel(reason);
  return "Anthropic traffic blocked — " + blockReasonLabel(reason);
}

export default function StatusCard({ status, checking, onCheck, onToggle }: Props) {
  if (!status) {
    return (
      <div
        className="flex flex-col items-center justify-center gap-3 h-[200px] text-[var(--text-muted)]"
        role="status"
        aria-label="Loading"
      >
        <div
          className="w-[22px] h-[22px] border-2 border-[var(--border)] border-t-[var(--blue)] rounded-full animate-spin"
          aria-hidden="true"
        />
        <span>Initializing...</span>
      </div>
    );
  }

  const { blocked, block_reason, ip_info, vpn_interface, vpn_active, guard_enabled } = status;

  const isUncertain = block_reason === "check_failed" || block_reason === "initializing";
  // The firewall refused to apply the rules and nothing is in force. This is the one
  // state that must never read as "allowed" — traffic flows and the user is exposed.
  const isUnprotected = block_reason === "firewall_error" && !blocked;

  return (
    <div className="flex flex-col gap-3">
      <section
        className={`block-indicator flex items-center gap-[14px] p-4 rounded-xl border transition-[background,border-color] duration-300 ${
          isUnprotected
            ? "bg-[var(--red-dim)] border-[var(--red-border)]"
            : blocked
              ? isUncertain
                ? "bg-[var(--yellow-dim)] border-[var(--yellow-border)]"
                : "bg-[var(--red-dim)] border-[var(--red-border)]"
              : "bg-[var(--green-dim)] border-[var(--green-border)]"
        }`}
        aria-label={
          !guard_enabled
            ? "Guard disabled — enable in Settings"
            : blockReasonAriaLabel(block_reason, blocked)
        }
      >
        <span className="text-[28px] leading-none" aria-hidden="true">
          {!guard_enabled
            ? "⚪"
            : isUnprotected
              ? "⚠️"
              : blocked
                ? isUncertain
                  ? "🟡"
                  : "🔴"
                : "🟢"}
        </span>
        <div>
          <p className="text-[15px] font-semibold">
            {!guard_enabled
              ? "Guard disabled"
              : isUnprotected
                ? "NOT protected"
                : blocked
                  ? "Anthropic BLOCKED"
                  : "Anthropic allowed"}
          </p>
          <p className="text-xs text-[var(--text-muted)] mt-0.5">
            {!guard_enabled ? "Enable in Settings" : blockReasonLabel(block_reason)}
          </p>
        </div>
      </section>

      <section
        className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl py-3 px-[14px]"
        aria-label="IP information"
      >
        <h2 className="text-[10px] font-semibold uppercase tracking-[0.8px] text-[var(--text-dim)] mb-[10px]">
          Your IP
        </h2>
        <dl>
          <div className="flex justify-between items-center py-[5px] border-b border-[var(--border-soft)] last:border-b-0">
            <dt className="text-[var(--text-muted)] text-xs">Address</dt>
            <dd className="text-xs text-right font-mono text-[11px]">{ip_info?.ip ?? "—"}</dd>
          </div>
          <div className="flex justify-between items-center py-[5px] border-b border-[var(--border-soft)] last:border-b-0">
            <dt className="text-[var(--text-muted)] text-xs">Country</dt>
            <dd className="text-xs flex items-center gap-[6px]">
              {ip_info?.country_code && (
                <span className="text-[18px] leading-none" aria-hidden="true">
                  {countryCodeToEmoji(ip_info.country_code)}
                </span>
              )}
              {ip_info?.country ?? "—"}
            </dd>
          </div>
          <div className="flex justify-between items-center py-[5px] border-b border-[var(--border-soft)] last:border-b-0">
            <dt className="text-[var(--text-muted)] text-xs">City</dt>
            <dd className="text-xs text-right">
              {ip_info ? [ip_info.city, ip_info.region].filter(Boolean).join(", ") : "—"}
            </dd>
          </div>
          <div className="flex justify-between items-center py-[5px] border-b border-[var(--border-soft)] last:border-b-0">
            <dt className="text-[var(--text-muted)] text-xs">Provider</dt>
            <dd
              className="text-[10px] text-right max-w-[220px] truncate font-mono"
              title={ip_info?.org}
            >
              {ip_info?.org ?? "—"}
            </dd>
          </div>
        </dl>
      </section>

      <section
        className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl py-3 px-[14px]"
        aria-label="VPN status"
      >
        <h2 className="text-[10px] font-semibold uppercase tracking-[0.8px] text-[var(--text-dim)] mb-[10px]">
          VPN
        </h2>
        <dl>
          <div className="flex justify-between items-center py-[5px] border-b border-[var(--border-soft)] last:border-b-0">
            <dt className="text-[var(--text-muted)] text-xs">Interface</dt>
            <dd
              className={`text-xs text-right ${vpn_interface ? "text-[var(--green)]" : "text-[var(--text-dim)]"}`}
            >
              {vpn_interface ?? "Not detected"}
            </dd>
          </div>
          <div className="flex justify-between items-center py-[5px] border-b border-[var(--border-soft)] last:border-b-0">
            <dt className="text-[var(--text-muted)] text-xs">State</dt>
            <dd
              className={`text-xs text-right ${vpn_active ? "text-[var(--green)]" : "text-[var(--text-dim)]"}`}
            >
              {vpn_active ? "Active" : "Inactive"}
            </dd>
          </div>
        </dl>
      </section>

      <div className="flex gap-2">
        <button
          className={`flex-1 py-[10px] min-h-9 rounded-[7px] border text-[13px] font-semibold cursor-pointer transition-[background,border-color,color] duration-150 ${
            guard_enabled
              ? "bg-transparent border-[var(--border)] text-[var(--text-muted)] hover:border-[var(--red)] hover:text-[var(--red)]"
              : "bg-[var(--blue)] border-[var(--blue)] text-white hover:brightness-110"
          }`}
          onClick={() => onToggle(!guard_enabled)}
          aria-label={guard_enabled ? "Disable protection" : "Enable protection"}
          aria-pressed={guard_enabled}
        >
          {guard_enabled ? "Disable" : "Enable protection"}
        </button>

        <button
          className={`flex-1 py-[10px] min-h-9 rounded-[7px] border text-[13px] font-medium cursor-pointer flex items-center justify-center gap-2 transition-colors duration-150 disabled:opacity-50 disabled:cursor-not-allowed ${
            checking
              ? "border-[var(--border)] text-[var(--text-muted)]"
              : "border-[var(--blue-dim)] bg-transparent text-[var(--blue)] hover:bg-[var(--blue-dim)]"
          }`}
          onClick={onCheck}
          disabled={checking || !guard_enabled}
          aria-label={checking ? "Checking IP, please wait" : "Check IP now"}
          aria-busy={checking}
        >
          {checking ? (
            <>
              <span
                className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"
                aria-hidden="true"
              />{" "}
              Checking...
            </>
          ) : (
            "Check now"
          )}
        </button>
      </div>
    </div>
  );
}
