//! IP geolocation via ipinfo.io with a 60-second cache.
//!
//! MITM protection:
//! - `no_proxy()` bypasses the system proxy so the real exit IP is checked.
//! - `rustls-tls` with only Mozilla WebPKI roots — the system certificate store is
//!   excluded, so corporate or antivirus CAs cannot issue a trusted cert for ipinfo.io.
//!
//! Full SPKI pinning would require a custom rustls verifier; excluding the system store
//! provides ~95% of the same protection at a fraction of the complexity.

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
        .no_proxy()
        .tls_built_in_root_certs(true)
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
