//! `{{FIELD}}` placeholder substitution for `kprun mcp` header/URL templates.

use std::collections::HashMap;

use crate::{KprunError, Result};

/// Substitute `{{FIELD}}` placeholders with values from `fields`.
///
/// Unknown fields and malformed placeholders are hard errors — no partial
/// substitution is ever returned.
pub fn substitute(template: &str, fields: &HashMap<String, String>) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err(KprunError::MalformedTemplate(format!(
                "unclosed '{{{{' in '{template}'"
            )));
        };
        let field = after[..end].trim();
        if field.is_empty() {
            return Err(KprunError::MalformedTemplate(format!(
                "empty field name in '{template}'"
            )));
        }
        let value = fields
            .get(field)
            .ok_or_else(|| KprunError::UnknownTemplateField(field.to_string()))?;
        out.push_str(value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn passes_through_text_without_placeholders() {
        let out = substitute("plain text", &fields(&[])).unwrap();
        assert_eq!(out, "plain text");
    }

    #[test]
    fn substitutes_single_field() {
        let out = substitute("Bearer {{TOKEN}}", &fields(&[("TOKEN", "abc123")])).unwrap();
        assert_eq!(out, "Bearer abc123");
    }

    #[test]
    fn substitutes_multiple_fields() {
        let out = substitute("{{A}}-{{B}}-{{A}}", &fields(&[("A", "x"), ("B", "y")])).unwrap();
        assert_eq!(out, "x-y-x");
    }

    #[test]
    fn unknown_field_is_hard_error() {
        let err = substitute("Bearer {{NOPE}}", &fields(&[("TOKEN", "t")])).unwrap_err();
        assert!(matches!(err, KprunError::UnknownTemplateField(f) if f == "NOPE"));
    }

    #[test]
    fn unclosed_placeholder_is_error() {
        let err = substitute("Bearer {{TOKEN", &fields(&[("TOKEN", "t")])).unwrap_err();
        assert!(matches!(err, KprunError::MalformedTemplate(_)));
    }

    #[test]
    fn empty_field_name_is_error() {
        let err = substitute("x{{}}y", &fields(&[])).unwrap_err();
        assert!(matches!(err, KprunError::MalformedTemplate(_)));
    }

    #[test]
    fn trims_whitespace_inside_braces() {
        let out = substitute("{{ TOKEN }}", &fields(&[("TOKEN", "t")])).unwrap();
        assert_eq!(out, "t");
    }
}
