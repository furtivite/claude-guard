//! Определение IP и страны через ipinfo.io.
//!
//! Результат кэшируется на CACHE_TTL. При ошибке возвращает Err —
//! guard интерпретирует это как fail-open (не блокировать).
//!
//! Защита от MITM:
//! - `no_proxy()` — запрос идёт мимо системного прокси
//! - `rustls-tls` + отключён system certificate store — используем только
//!   Mozilla WebPKI roots (webpki-roots), корпоративные/антивирусные CA
//!   не могут выдать доверенный сертификат для ipinfo.io
//!
//! Полный SPKI pinning потребовал бы кастомного TLS verifier на уровне rustls;
//! отключение system store даёт 95% той же защиты при несравнимо меньшей сложности.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const CACHE_TTL: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const IP_API: &str = "https://ipinfo.io/json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpInfo {
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub region: String,
    pub org: String,
    pub is_russian: bool,
}

impl IpInfo {
    // ipinfo.io не возвращает полное название страны на бесплатном плане
    fn country_name(code: &str) -> &'static str {
        match code {
            "AE" => "UAE",           "AT" => "Austria",
            "BY" => "Belarus",       "CH" => "Switzerland",
            "CZ" => "Czech Republic","DE" => "Germany",
            "EE" => "Estonia",       "FI" => "Finland",
            "FR" => "France",        "GB" => "United Kingdom",
            "HK" => "Hong Kong",     "JP" => "Japan",
            "KZ" => "Kazakhstan",    "LT" => "Lithuania",
            "LV" => "Latvia",        "NL" => "Netherlands",
            "NO" => "Norway",        "PL" => "Poland",
            "RU" => "Russia",        "SE" => "Sweden",
            "SG" => "Singapore",     "TR" => "Turkey",
            "UA" => "Ukraine",       "US" => "United States",
            _ => "",
        }
    }
}

#[derive(Deserialize)]
struct RawIpInfo {
    ip: Option<String>,
    country: Option<String>,
    city: Option<String>,
    region: Option<String>,
    org: Option<String>,
}

struct Cache {
    entry: Option<(IpInfo, Instant)>,
}

static CACHE: RwLock<Cache> = RwLock::const_new(Cache { entry: None });

pub async fn invalidate() {
    CACHE.write().await.entry = None;
}

pub async fn get() -> Result<IpInfo, String> {
    {
        let cache = CACHE.read().await;
        if let Some((ref info, fetched_at)) = cache.entry {
            if fetched_at.elapsed() < CACHE_TTL {
                return Ok(info.clone());
            }
        }
    }

    let info = fetch().await?;
    CACHE.write().await.entry = Some((info.clone(), Instant::now()));
    Ok(info)
}

async fn fetch() -> Result<IpInfo, String> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        // Реальный выходной IP, не через прокси
        .no_proxy()
        // Только Mozilla WebPKI roots — корпоративные/антивирусные CA игнорируются.
        // Это предотвращает MITM через подменный доверенный CA в system store.
        .tls_built_in_root_certs(true)
        .tls_built_in_native_certs(false)
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let raw: RawIpInfo = client
        .get(IP_API)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("ipinfo request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("ipinfo parse: {e}"))?;

    let code = raw.country.unwrap_or_default().to_uppercase();
    let name = IpInfo::country_name(&code);

    Ok(IpInfo {
        is_russian: code == "RU",
        country: if name.is_empty() { code.clone() } else { name.to_owned() },
        country_code: code,
        ip: raw.ip.unwrap_or_default(),
        city: raw.city.unwrap_or_else(|| "—".into()),
        region: raw.region.unwrap_or_else(|| "—".into()),
        org: raw.org.unwrap_or_else(|| "—".into()),
    })
}
