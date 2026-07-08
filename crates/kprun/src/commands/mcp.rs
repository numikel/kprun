use std::time::Duration;

use kprun_core::audit::{log_access, AuditRecord};
use kprun_core::config::Config;
use kprun_core::template;
use kprun_core::unlock::{unlock_noninteractive, UnlockContext};
use kprun_core::vault::{open_vault, OpenMode};
use kprun_core::{KprunError, Result};

use crate::cli::McpTransport;
use crate::mcp_bridge::{run_bridge, BridgeConfig, Transport};

pub fn execute(
    entry: String,
    headers: Vec<String>,
    bearer: Option<String>,
    transport: McpTransport,
    timeout: u64,
    allow_insecure_http: bool,
    url: String,
) -> i32 {
    match mcp_inner(
        entry,
        headers,
        bearer,
        transport,
        timeout,
        allow_insecure_http,
        url,
    ) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn mcp_inner(
    entry: String,
    headers: Vec<String>,
    bearer: Option<String>,
    transport: McpTransport,
    timeout: u64,
    allow_insecure_http: bool,
    url: String,
) -> Result<i32> {
    let cfg = Config::from_env();
    let ctx = UnlockContext {
        keyfile: cfg.keyfile.clone(),
        db_path: cfg.db_path.clone(),
    };
    let key = unlock_noninteractive(&ctx)?;
    let vault = open_vault(&cfg.db_path, key, OpenMode::ReadOnly)?;
    let id = vault.find_entry_by_title(&entry)?;
    let fields = vault.entry_custom_values(id);

    let mut templates: Vec<(String, String)> = Vec::new();
    for spec in &headers {
        let (name, value) = spec.split_once(':').ok_or_else(|| {
            KprunError::Other(format!(
                "invalid --header '{spec}': expected 'Name: template'"
            ))
        })?;
        let name = name.trim();
        if name.is_empty() {
            return Err(KprunError::Other(format!(
                "invalid --header '{spec}': empty header name"
            )));
        }
        templates.push((name.to_string(), value.trim().to_string()));
    }
    if let Some(field) = &bearer {
        templates.push((
            "Authorization".to_string(),
            format!("Bearer {{{{{field}}}}}"),
        ));
    }

    // Resolve everything before touching the network — an unknown field
    // must fail fast, before any request or audit record.
    let resolved_url = template::substitute(&url, &fields)?;

    // Validate the resolved URL before ureq can see it: ureq's BadUri error
    // echoes the full URI, and the resolved query string may contain
    // substituted secrets. On failure cite only the user-typed template.
    let parsed: ureq::http::Uri = resolved_url.parse().map_err(|_| {
        KprunError::Other(format!(
            "invalid URL after substitution (template: '{url}')"
        ))
    })?;
    if parsed.scheme_str().is_none() || parsed.host().is_none() {
        return Err(KprunError::Other(format!(
            "URL must be absolute with scheme and host (template: '{url}')"
        )));
    }

    // Refuse plaintext credentials to a non-loopback host. A `{{` in the
    // user-typed URL template means at least one vault field was substituted
    // into the URL (substitute() already succeeded), which is the same
    // exposure as a secret header.
    let has_secret_material = bearer.is_some() || !headers.is_empty() || url.contains("{{");
    let is_http = parsed
        .scheme_str()
        .is_some_and(|s| s.eq_ignore_ascii_case("http"));
    let host = host_of(&resolved_url);
    if is_http && has_secret_material && !is_loopback_host(&host) && !allow_insecure_http {
        return Err(KprunError::Other(format!(
            "refusing to send vault-backed credentials over plaintext http:// \
             to non-loopback host '{host}'; use https:// or pass \
             --allow-insecure-http to accept the risk"
        )));
    }

    let mut resolved_headers: Vec<(String, String)> = Vec::new();
    for (name, tpl) in &templates {
        resolved_headers.push((name.clone(), template::substitute(tpl, &fields)?));
    }

    // Audit: entry name + header NAMES + host only (the query string may
    // contain substituted secrets). Never values.
    let header_names: Vec<String> = templates.iter().map(|(name, _)| name.clone()).collect();
    log_access(
        &cfg,
        &AuditRecord::new(
            &cfg.db_path,
            vec![entry],
            header_names,
            Some(format!("mcp {host}")),
        ),
    )?;

    run_bridge(BridgeConfig {
        url: resolved_url,
        headers: resolved_headers,
        transport: match transport {
            McpTransport::Auto => Transport::Auto,
            McpTransport::StreamableHttp => Transport::Streamable,
            McpTransport::Sse => Transport::LegacySse,
        },
        timeout: Duration::from_secs(timeout),
    })
}

fn host_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    // Strip `user:pass@` / `user@` userinfo. Bracketed IPv6 hosts never
    // contain '@', so splitting on the last '@' in the authority is safe.
    authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
        .to_string()
}

/// Loopback per the design: 127.0.0.0/8, ::1 (bracketed or not), and
/// `localhost` (case-insensitive), with any `:port` suffix stripped.
fn is_loopback_host(host: &str) -> bool {
    // Bare IP without port (covers unbracketed `::1`).
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    let bare = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    bare.eq_ignore_ascii_case("localhost")
}

#[cfg(test)]
mod tests {
    use super::host_of;
    use super::is_loopback_host;

    #[test]
    fn host_of_strips_path_and_query() {
        assert_eq!(
            host_of("https://api.example.com/mcp/?k=secret"),
            "api.example.com"
        );
        assert_eq!(host_of("http://127.0.0.1:8080/x"), "127.0.0.1:8080");
        assert_eq!(host_of("no-scheme/path"), "no-scheme");
    }

    #[test]
    fn host_of_strips_userinfo() {
        assert_eq!(host_of("http://user@localhost:1234/foo"), "localhost:1234");
        assert_eq!(host_of("http://user:pass@127.0.0.1/x"), "127.0.0.1");
        assert_eq!(host_of("http://user@[::1]:8080/y"), "[::1]:8080");
    }

    #[test]
    fn loopback_hosts_are_recognized() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.1:8080"));
        assert!(is_loopback_host("127.255.0.7"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("[::1]:8080"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST:3000"));
        // Regression: userinfo must already be stripped by host_of() before
        // reaching is_loopback_host(), or a URL like `http://user@localhost`
        // is wrongly treated as non-loopback.
        assert!(is_loopback_host(&host_of("http://user@localhost:1234/foo")));
    }

    #[test]
    fn non_loopback_hosts_are_rejected() {
        assert!(!is_loopback_host("api.example.com"));
        assert!(!is_loopback_host("localhost.evil"));
        assert!(!is_loopback_host("128.0.0.1"));
        assert!(!is_loopback_host("[2001:db8::1]:443"));
        assert!(!is_loopback_host(""));
    }
}
