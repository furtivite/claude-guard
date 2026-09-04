//! IP geolocation with a 60-second cache.
//!
//! Several independent providers are queried in parallel rather than trusting one.
//! A single service that is unreachable, rate-limited, or wrong no longer decides
//! whether the machine is protected.
//!
//! Disagreement resolves toward blocking: if *any* provider reports RU, the verdict
//! is RU. Convincing the guard that a Russian exit IP is safe therefore requires
//! every provider to say so, while blocking needs only one — the asymmetry matches
//! the app's fail-closed policy.
//!
//! MITM protection:
//! - `no_proxy()` bypasses the system proxy so the real exit IP is checked.
//! - The `rustls-tls` feature (with `default-features = false` in Cargo.toml) uses
//!   only the bundled Mozilla `webpki-roots`; the OS certificate store is never
//!   consulted, so a corporate or antivirus CA installed on the machine cannot
//!   issue a trusted cert for the providers.
//!
//! Full SPKI pinning would require a custom rustls verifier; excluding the system
//! store gives most of that protection at a fraction of the complexity.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const CACHE_TTL: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

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
    // The free tiers do not return a full country name
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

    /// Pure classification of a raw country field into the fields we store.
    /// Extracted from the providers so it can be unit-tested without network access.
    ///
    /// "RUSSIA" is accepted alongside "RU" on purpose. Providers differ on whether
    /// the field holds an ISO code or a full name, and a field that silently stops
    /// being a code would otherwise turn a Russian exit IP into a non-match — a
    /// fail-open. Matching both costs nothing and removes that class of bug.
    fn classify(raw_country: Option<String>) -> (bool, String, String) {
        let raw = raw_country.unwrap_or_default().to_uppercase();
        let is_russian = raw == "RU" || raw == "RUSSIA";
        let code = if raw == "RUSSIA" { "RU".to_string() } else { raw };
        let name = Self::country_name(&code);
        let country = if name.is_empty() { code.clone() } else { name.to_owned() };
        (is_russian, country, code)
    }
}

/// Where a reading came from, for logging and for preferring the richest response.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Provider {
    /// Returns city and organisation as well as the country.
    IpInfo,
    CountryIs,
    IfConfig,
}

impl Provider {
    const ALL: [Provider; 3] = [Provider::IpInfo, Provider::CountryIs, Provider::IfConfig];

    fn url(self) -> &'static str {
        match self {
            Provider::IpInfo => "https://ipinfo.io/json",
            Provider::CountryIs => "https://api.country.is/",
            Provider::IfConfig => "https://ifconfig.co/json",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Provider::IpInfo => "ipinfo.io",
            Provider::CountryIs => "country.is",
            Provider::IfConfig => "ifconfig.co",
        }
    }

    /// True for the one provider that supplies city/region/org, so its reading is
    /// preferred for display when the verdict is the same either way.
    fn is_detailed(self) -> bool {
        self == Provider::IpInfo
    }
}

/// The union of the provider response shapes. Every field is optional: a provider
/// that omits one simply contributes nothing to it.
#[derive(Deserialize, Default)]
struct RawIpInfo {
    ip: Option<String>,
    country: Option<String>,
    country_iso: Option<String>,
    city: Option<String>,
    region: Option<String>,
    region_name: Option<String>,
    org: Option<String>,
    asn_org: Option<String>,
}

impl RawIpInfo {
    fn into_info(self) -> IpInfo {
        // `country_iso` first: ifconfig.co supplies both, and there its `country` is
        // a full name ("Russia") while ipinfo and country.is put the ISO code in
        // `country`. Reading `country` first would classify ifconfig.co by name.
        let (is_russian, country, country_code) =
            IpInfo::classify(self.country_iso.or(self.country));

        IpInfo {
            is_russian,
            country,
            country_code,
            ip: self.ip.unwrap_or_default(),
            city: self.city.unwrap_or_else(|| "—".into()),
            region: self.region.or(self.region_name).unwrap_or_else(|| "—".into()),
            org: self.org.or(self.asn_org).unwrap_or_else(|| "—".into()),
        }
    }
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

/// Combines what the providers returned into a single verdict.
///
/// Pure so the precedence rules can be tested without touching the network.
/// Readings are `(provider is detailed, reading)` pairs.
fn combine(readings: Vec<(bool, IpInfo)>, errors: Vec<String>) -> Result<IpInfo, String> {
    if readings.is_empty() {
        return Err(format!("every IP provider failed: {}", errors.join("; ")));
    }

    // One RU reading is enough. Show that provider's data, so the UI explains the
    // block with the evidence that caused it.
    if let Some((_, russian)) = readings.iter().find(|(_, i)| i.is_russian) {
        return Ok(russian.clone());
    }

    // Unanimously non-RU: prefer the reading that carries city and organisation.
    let best = readings.iter().find(|(detailed, _)| *detailed).unwrap_or(&readings[0]);
    Ok(best.1.clone())
}

async fn fetch() -> Result<IpInfo, String> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .no_proxy()
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    // Queried together rather than in sequence: three timeouts back to back would
    // stall a check cycle. The tuple order must match Provider::ALL.
    let (ipinfo, country_is, ifconfig) = tokio::join!(
        fetch_one(&client, Provider::IpInfo),
        fetch_one(&client, Provider::CountryIs),
        fetch_one(&client, Provider::IfConfig),
    );
    let results = [ipinfo, country_is, ifconfig];

    let mut readings = Vec::new();
    let mut errors = Vec::new();
    for (provider, result) in Provider::ALL.iter().zip(results) {
        match result {
            Ok(info) => {
                log::debug!("{}: {} ({})", provider.name(), info.country_code, info.ip);
                readings.push((provider.is_detailed(), info));
            }
            Err(e) => errors.push(format!("{}: {e}", provider.name())),
        }
    }

    if !errors.is_empty() {
        log::warn!(
            "{} of {} IP providers failed: {}",
            errors.len(),
            Provider::ALL.len(),
            errors.join("; ")
        );
    }
    combine(readings, errors)
}

async fn fetch_one(client: &reqwest::Client, provider: Provider) -> Result<IpInfo, String> {
    let raw: RawIpInfo = client
        .get(provider.url())
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("parse: {e}"))?;

    Ok(raw.into_info())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(code: &str, city: &str) -> IpInfo {
        let (is_russian, country, country_code) = IpInfo::classify(Some(code.into()));
        IpInfo {
            is_russian,
            country,
            country_code,
            ip: "1.2.3.4".into(),
            city: city.into(),
            region: "—".into(),
            org: "—".into(),
        }
    }

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

    #[test]
    fn full_country_name_is_still_recognised_as_russia() {
        let (is_ru, country, code) = IpInfo::classify(Some("Russia".into()));
        assert!(is_ru);
        assert_eq!(country, "Russia");
        assert_eq!(code, "RU");
    }

    #[test]
    fn iso_field_wins_over_the_full_name_field() {
        // Shaped like a real ifconfig.co response, which carries both.
        let raw = RawIpInfo {
            country: Some("Russia".into()),
            country_iso: Some("RU".into()),
            ..Default::default()
        };
        let info = raw.into_info();
        assert!(info.is_russian);
        assert_eq!(info.country_code, "RU");
    }

    #[test]
    fn code_only_providers_are_unaffected() {
        // ipinfo.io and country.is put the ISO code in `country` and omit country_iso.
        let raw = RawIpInfo { country: Some("ru".into()), ..Default::default() };
        assert!(raw.into_info().is_russian);
    }

    #[test]
    fn no_readings_is_an_error() {
        let out = combine(vec![], vec!["a: down".into()]);
        assert!(out.is_err());
    }

    #[test]
    fn a_single_russian_reading_outvotes_the_others() {
        let out =
            combine(vec![(true, info("DE", "Berlin")), (false, info("RU", "Moscow"))], vec![])
                .expect("readings present");
        assert!(out.is_russian);
        assert_eq!(out.city, "Moscow");
    }

    #[test]
    fn unanimous_non_russian_prefers_the_detailed_provider() {
        let out = combine(vec![(false, info("DE", "—")), (true, info("DE", "Berlin"))], vec![])
            .expect("readings present");
        assert!(!out.is_russian);
        assert_eq!(out.city, "Berlin");
    }

    #[test]
    fn a_lone_surviving_provider_still_decides() {
        let out = combine(vec![(false, info("NL", "—"))], vec!["ipinfo: timeout".into()])
            .expect("one reading is enough");
        assert!(!out.is_russian);
        assert_eq!(out.country_code, "NL");
    }
}
