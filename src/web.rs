// Minimal HTTP client for HEIDES web grounding.
// Uses ureq with a browser friendly user agent and short timeouts so the
// harness stays responsive even when the network is slow.

use std::time::Duration;

pub const USER_AGENT: &str = "heides/0.2 (code nervous system)";

fn req_timeout() -> std::time::Duration {
    Duration::from_secs(15)
}

/// GET a URL and return the response body as text.
pub fn get(url: &str) -> Result<String, String> {
    let mut resp = ureq::get(url)
        .header("User-Agent", USER_AGENT)
        .config()
        .timeout_global(Some(req_timeout()))
        .build()
        .call()
        .map_err(|e| e.to_string())?;
    resp.body_mut().read_to_string().map_err(|e| e.to_string())
}

/// POST a JSON body and return the response body as text.
pub fn post_json(url: &str, body: &str) -> Result<String, String> {
    let mut resp = ureq::post(url)
        .header("User-Agent", USER_AGENT)
        .header("Content-Type", "application/json")
        .config()
        .timeout_global(Some(req_timeout()))
        .build()
        .send(body.as_bytes().to_vec())
        .map_err(|e| e.to_string())?;
    resp.body_mut().read_to_string().map_err(|e| e.to_string())
}
