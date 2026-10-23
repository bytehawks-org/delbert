//! JSON Canonicalization Scheme (RFC 8785), restricted to what Delbert needs:
//! numbers must be integers within ±(2^53 - 1) (I-JSON safe); floats are rejected.

use serde_json::Value;

const MAX_SAFE: i64 = (1 << 53) - 1;

#[derive(Debug, thiserror::Error)]
pub enum CanonError {
    #[error("floating point or out-of-range number not allowed: {0}")]
    Number(String),
}

/// Canonical UTF-8 bytes of a JSON value.
pub fn to_vec(value: &Value) -> Result<Vec<u8>, CanonError> {
    let mut out = String::new();
    write(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write(value: &Value, out: &mut String) -> Result<(), CanonError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let ok = n.as_i64().is_some_and(|i| i.abs() <= MAX_SAFE) || n.as_u64().is_some_and(|u| u <= MAX_SAFE as u64);
            if !ok {
                return Err(CanonError::Number(n.to_string()));
            }
            out.push_str(&n.to_string());
        }
        // serde_json escapes exactly what JCS requires: `"`, `\`, and control
        // characters (short forms for \b \t \n \f \r, lowercase \u00xx otherwise).
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string serializes")),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // JCS sorts keys by UTF-16 code units, which differs from UTF-8 order
            // for characters outside the BMP.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("string serializes"));
                out.push(':');
                write(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn c(v: Value) -> String {
        String::from_utf8(to_vec(&v).unwrap()).unwrap()
    }

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        assert_eq!(c(json!({"b": 1, "a": [true, null, "x"], "c": {"z": 0, "y": 1}})), r#"{"a":[true,null,"x"],"b":1,"c":{"y":1,"z":0}}"#);
    }

    #[test]
    fn keys_sort_by_utf16_not_utf8() {
        // U+10000 is a surrogate pair (0xD800..) in UTF-16, so it sorts BEFORE U+FFFF,
        // while in UTF-8/code point order it would come after.
        let v = json!({"\u{ffff}": 1, "\u{10000}": 2});
        assert_eq!(c(v), "{\"\u{10000}\":2,\"\u{ffff}\":1}");
    }

    #[test]
    fn escapes_like_rfc8785() {
        assert_eq!(c(json!("a\"b\\c\n\u{1}\u{7f}")), "\"a\\\"b\\\\c\\n\\u0001\u{7f}\"");
    }

    #[test]
    fn floats_and_huge_ints_are_rejected() {
        assert!(to_vec(&json!(1.5)).is_err());
        assert!(to_vec(&json!(9007199254740993_i64)).is_err());
        assert!(to_vec(&json!(-5)).is_ok());
    }

    #[test]
    fn is_idempotent() {
        let once = to_vec(&json!({"b": [1, {"d": 1, "c": 2}], "a": "x"})).unwrap();
        let again = to_vec(&serde_json::from_slice::<Value>(&once).unwrap()).unwrap();
        assert_eq!(once, again);
    }
}
