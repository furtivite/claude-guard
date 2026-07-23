//! IP geolocation via ipinfo.io with a 60-second cache.
//!
//! MITM protection:
//! - `no_proxy()` bypasses the system proxy so the real exit IP is checked.
//! - The `rustls-tls` feature (with `default-features = false` in Cargo.toml) uses
//!   only the bundled Mozilla `webpki-roots`; the OS certificate store is never
//!   consulted, so a corporate or antivirus CA installed on the machine cannot
//!   issue a trusted cert for ipinfo.io.
//!
//! Full SPKI pinning would require a custom rustls verifier; excluding the system
//! store gives most of that protection at a fraction of the complexity.

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
    // ipinfo.io free tier does not return a full country name
    #[rustfmt::skip]
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

    /// Pure classification of a raw ipinfo country field into the fields we store.
    /// Extracted from `fetch` so it can be unit-tested without network access.
    fn classify(raw_country: Option<String>) -> (bool, String, String) {
        let code = raw_country.unwrap_or_default().to_uppercase();
        let name = Self::country_name(&code);
        let country = if name.is_empty() { code.clone() } else { name.to_owned() };
        (code == "RU", country, code)
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
        .no_proxy()
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

    let (is_russian, country, country_code) = IpInfo::classify(raw.country);

    Ok(IpInfo {
        is_russian,
        country,
        country_code,
        ip: raw.ip.unwrap_or_default(),
        city: raw.city.unwrap_or_else(|| "—".into()),
        region: raw.region.unwrap_or_else(|| "—".into()),
        org: raw.org.unwrap_or_else(|| "—".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_code_is_flagged() {
        let (is_ru, country, code) = IpInfo::classify(Some("ru".into()));
        assert!(is_ru);
        assert_eq!(country, "Russia");
        assert_eq!(code, "RU");
    }

    #[test]
    fn non_russian_code_is_not_flagged() {
        let (is_ru, country, code) = IpInfo::classify(Some("de".into()));
        assert!(!is_ru);
        assert_eq!(country, "Germany");
        assert_eq!(code, "DE");
    }

    #[test]
    fn unknown_code_falls_back_to_code_as_name() {
        let (is_ru, country, code) = IpInfo::classify(Some("zz".into()));
        assert!(!is_ru);
        assert_eq!(country, "ZZ");
        assert_eq!(code, "ZZ");
    }

    #[test]
    fn missing_country_is_not_russian() {
        let (is_ru, country, code) = IpInfo::classify(None);
        assert!(!is_ru);
        assert_eq!(country, "");
        assert_eq!(code, "");
    }
}
