export interface IpInfo {
  ip: string;
  country: string;
  country_code: string;
  city: string;
  region: string;
  org: string;
  is_russian: boolean;
  /** Provider behind the reading shown. */
  source: string;
  /** What the other providers that answered reported, as "name: CODE". */
  others: string[];
}

export type BlockReason =
  "none" | "russian_ip" | "vpn_inactive" | "check_failed" | "initializing" | "firewall_error";

export interface GuardStatus {
  blocked: boolean;
  block_reason: BlockReason;
  ip_info: IpInfo | null;
  vpn_interface: string | null;
  vpn_active: boolean;
  guard_enabled: boolean;
  last_check: string | null;
  error: string | null;
}

export type VpnMode = "ip_only" | "port" | "process";

export interface Settings {
  enabled: boolean;
  check_interval: number;
  show_tray: boolean;
  autostart: boolean;
  vpn_mode: VpnMode;
  vpn_port: number;
  vpn_process: string;
}
