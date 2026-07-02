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
    url: String,
) -> i32 {
    match mcp_inner(entry, headers, bearer, transport, timeout, url) {
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
            cfg.db_path.clone(),
            vec![entry],
            header_names,
            Some(format!("mcp {}", host_of(&resolved_url))),
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
    rest.split(['/', '?']).next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn host_of_strips_path_and_query() {
        assert_eq!(
            host_of("https://api.example.com/mcp/?k=secret"),
            "api.example.com"
        );
        assert_eq!(host_of("http://127.0.0.1:8080/x"), "127.0.0.1:8080");
        assert_eq!(host_of("no-scheme/path"), "no-scheme");
    }
}
