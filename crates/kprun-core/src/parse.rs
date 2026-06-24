use crate::{KprunError, Result};

pub fn parse_key_val(input: &str) -> Result<(String, String)> {
    let Some((key, value)) = input.split_once('=') else {
        return Err(KprunError::InvalidKeyVal);
    };
    if key.is_empty() {
        return Err(KprunError::EmptyKey);
    }
    Ok((key.to_string(), value.to_string()))
}

pub fn parse_key_vals<'a, I>(items: I) -> Result<Vec<(String, String)>>
where
    I: IntoIterator<Item = &'a str>,
{
    items.into_iter().map(parse_key_val).collect()
}

#[cfg(test)]
mod tests {
    use crate::parse::{parse_key_val, parse_key_vals};
    use crate::KprunError;

    #[test]
    fn parse_simple_key_val() {
        let (k, v) = parse_key_val("GITHUB_TOKEN=ghp_abc").unwrap();
        assert_eq!(k, "GITHUB_TOKEN");
        assert_eq!(v, "ghp_abc");
    }

    #[test]
    fn parse_value_with_equals() {
        let (k, v) = parse_key_val("CONN=host=1;pass=2").unwrap();
        assert_eq!(k, "CONN");
        assert_eq!(v, "host=1;pass=2");
    }

    #[test]
    fn parse_rejects_missing_equals() {
        let err = parse_key_val("NOEQUALS").unwrap_err();
        assert!(matches!(err, KprunError::InvalidKeyVal));
    }

    #[test]
    fn parse_errors_do_not_echo_full_input() {
        let e1 = parse_key_val("no-equals-but-sensitive").unwrap_err();
        assert!(!e1.to_string().contains("no-equals-but-sensitive"));
        let e2 = parse_key_val("=value-after-empty-key").unwrap_err();
        assert!(!e2.to_string().contains("value-after-empty-key"));
    }

    #[test]
    fn parse_multiple() {
        let pairs = parse_key_vals(["A=1", "B=2"]).unwrap();
        assert_eq!(
            pairs,
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
    }
}
