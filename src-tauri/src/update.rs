//! On-demand update check against GitHub Releases. Nothing is downloaded or
//! run: the user is shown the newest version and the release page.

use serde::Serialize;
use std::time::Duration;

const RELEASES_API: &str = "https://api.github.com/repos/jonios/alizy/releases/latest";
pub const RELEASES_PAGE: &str = "https://github.com/jonios/alizy/releases/latest";
const RELEASE_URL_PREFIX: &str = "https://github.com/jonios/alizy/releases/";

#[derive(Debug, Serialize, PartialEq)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: String,
    pub update_available: bool,
    pub url: String,
}

/// `1.2.3`, `v1.2.3`, `1.2.3-rc.1` → (1, 2, 3, is_prerelease).
fn parse_version(s: &str) -> Option<(u64, u64, u64, bool)> {
    let s = s.trim().trim_start_matches('v');
    let (core, pre) = match s.split_once(['-', '+']) {
        Some((c, rest)) => (c, s[c.len()..].starts_with('-') && !rest.is_empty()),
        None => (s, false),
    };
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (it.next()??, it.next()??, it.next()??);
    if it.next().is_some() {
        return None;
    }
    Some((v.0, v.1, v.2, pre))
}

fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some((a, b, c, lp)), Some((x, y, z, cp))) => (a, b, c) > (x, y, z) || ((a, b, c) == (x, y, z) && cp && !lp),
        _ => false,
    }
}

pub fn evaluate(current: &str, body: &str) -> Result<UpdateInfo, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|_| "unexpected answer from GitHub".to_string())?;
    let tag = v["tag_name"].as_str().ok_or("the latest release has no version tag")?;
    if parse_version(tag).is_none() {
        return Err(format!("the latest release has an unrecognised version tag `{tag}`"));
    }
    let url = v["html_url"]
        .as_str()
        .filter(|u| u.starts_with(RELEASE_URL_PREFIX))
        .unwrap_or(RELEASES_PAGE)
        .to_string();
    Ok(UpdateInfo {
        current: current.to_string(),
        latest: tag.trim_start_matches('v').to_string(),
        update_available: is_newer(tag, current),
        url,
    })
}

pub fn check(current: &str) -> Result<UpdateInfo, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .user_agent("Alizy")
        .build();
    let resp = agent
        .get(RELEASES_API)
        .set("Accept", "application/vnd.github+json")
        .call();
    let body = match resp {
        Ok(r) => r.into_string().map_err(|e| e.to_string())?,
        Err(ureq::Error::Status(404, _)) => return Err("No release has been published yet.".into()),
        Err(ureq::Error::Status(code, _)) => return Err(format!("GitHub answered HTTP {code}; try again later.")),
        Err(e) => return Err(format!("Could not reach GitHub: {e}")),
    };
    evaluate(current, &body)
}

/// Opens the fixed releases page in the default browser. AppImage runtimes
/// prepend their bundled libraries; the browser must not inherit them.
pub fn open_releases_page() -> Result<(), String> {
    let mut cmd = std::process::Command::new("xdg-open");
    cmd.arg(RELEASES_PAGE);
    for var in [
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "GTK_PATH",
        "GTK_EXE_PREFIX",
        "GTK_DATA_PREFIX",
        "GDK_PIXBUF_MODULE_FILE",
        "GDK_PIXBUF_MODULEDIR",
        "GIO_EXTRA_MODULES",
        "GSETTINGS_SCHEMA_DIR",
        "GST_PLUGIN_SYSTEM_PATH",
        "PYTHONHOME",
        "PYTHONPATH",
    ] {
        cmd.env_remove(var);
    }
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("could not open a browser: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("0.2.0", "0.2.0-rc.1"));
        assert!(!is_newer("0.2.0-rc.1", "0.2.0"));
        assert!(!is_newer("garbage", "0.1.0"));
        assert!(!is_newer("0.1", "0.1.0"));
    }

    #[test]
    fn evaluates_release_json() {
        let body = r#"{"tag_name":"v0.2.0","html_url":"https://github.com/jonios/alizy/releases/tag/v0.2.0"}"#;
        let u = evaluate("0.1.0", body).unwrap();
        assert!(u.update_available);
        assert_eq!(u.latest, "0.2.0");
        assert_eq!(u.url, "https://github.com/jonios/alizy/releases/tag/v0.2.0");
    }

    #[test]
    fn foreign_url_is_replaced_by_the_fixed_page() {
        let body = r#"{"tag_name":"v0.2.0","html_url":"https://evil.example/alizy"}"#;
        assert_eq!(evaluate("0.1.0", body).unwrap().url, RELEASES_PAGE);
    }

    #[test]
    fn rejects_bad_tags() {
        assert!(evaluate("0.1.0", r#"{"tag_name":"nightly"}"#).is_err());
        assert!(evaluate("0.1.0", "not json").is_err());
    }
}
