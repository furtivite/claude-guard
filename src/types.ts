// Единственный источник типов для всего UI.
// Структуры зеркалят Rust-сериализацию из guard.rs и config.rs.

export interface IpInfo {
  ip: string;
  country: string;
  country_code: string;
  city: string;
  region: string;
  org: string;
  is_russian: boolean;
}

// Зеркало BlockReason из guard.rs
export type BlockReason =
  | "none"           // не заблокировано
  | "russian_ip"     // IP принадлежит России
  | "vpn_inactive"   // VPN не активен (режим port/process)
  | "check_failed"   // ipinfo.io недоступен, правила сохранены
  | "initializing";  // первый старт, проверка ещё не завершена

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
  vpn_mode: VpnMode;
  vpn_port: number;
  vpn_process: string;
}
