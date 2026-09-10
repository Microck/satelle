//! TOON 4.1 encoding of the canonical JSON data model.
//!
//! Keep this at the presentation boundary: it does not change Serde's JSON
//! features or durable payload ordering. The checked-in reference cases come
//! from @toon-format/toon 4.1.1. There is no Satelle-specific wire dialect.

use serde_json::{Map, Value};
use std::fmt::Write;

pub(super) fn encode(value: &Value) -> String {
    let mut encoder = Encoder(String::new());
    match value {
        Value::Object(object) => encoder.object(object, 0, None),
        Value::Array(array) if array.is_empty() => encoder.0.push_str("[]\n"),
        Value::Array(array) => encoder.array(array, 0, true),
        _ => {
            encoder.primitive(value);
            encoder.0.push('\n');
        }
    }
    // TOON documents have no trailing LF. The CLI supplies its record terminator.
    encoder.0.pop();
    encoder.0
}

struct Encoder(String);

impl Encoder {
    fn indent(&mut self, depth: usize) {
        for _ in 0..depth {
            self.0.push_str("  ");
        }
    }

    fn object(&mut self, object: &Map<String, Value>, depth: usize, key: Option<&str>) {
        if let Some(key) = key {
            self.key(key);
        }
        let columns = (object.len() >= 2)
            .then(|| table_columns(object.values()))
            .flatten();
        if let Some(columns) = columns {
            self.table_header(object.len(), true, &columns);
            for (key, value) in object {
                self.indent(depth + 1);
                self.key(key);
                self.0.push_str(": ");
                self.cells(value, &columns);
                self.0.push('\n');
            }
        } else {
            let field_depth = if key.is_some() {
                self.0.push_str(":\n");
                depth + 1
            } else {
                depth
            };
            for (key, value) in object {
                self.indent(field_depth);
                self.field(key, value, field_depth);
            }
        }
    }

    fn field(&mut self, key: &str, value: &Value, depth: usize) {
        if let Value::Object(object) = value {
            self.object(object, depth, Some(key));
            return;
        }
        self.key(key);
        match value {
            Value::Array(array) if array.is_empty() => self.0.push_str(": []\n"),
            Value::Array(array) => self.array(array, depth, true),
            _ => {
                self.0.push_str(": ");
                self.primitive(value);
                self.0.push('\n');
            }
        }
    }

    fn array(&mut self, array: &[Value], depth: usize, allow_table: bool) {
        if array.iter().all(is_primitive) {
            write!(self.0, "[{}]:", array.len()).unwrap();
            if !array.is_empty() {
                self.0.push(' ');
                for (index, value) in array.iter().enumerate() {
                    if index != 0 {
                        self.0.push(',');
                    }
                    self.primitive(value);
                }
            }
            self.0.push('\n');
            return;
        }
        if let Some(columns) = allow_table.then(|| table_columns(array.iter())).flatten() {
            self.table_header(array.len(), false, &columns);
            for value in array {
                self.indent(depth + 1);
                self.cells(value, &columns);
                self.0.push('\n');
            }
            return;
        }
        writeln!(self.0, "[{}]:", array.len()).unwrap();
        for value in array {
            self.list_item(value, depth + 1);
        }
    }

    fn list_item(&mut self, value: &Value, depth: usize) {
        self.indent(depth);
        self.0.push('-');
        match value {
            Value::Object(object) => {
                let mut fields = object.iter();
                if let Some((key, value)) = fields.next() {
                    self.0.push(' ');
                    // The first field occupies depth +1 even on the hyphen line.
                    // Its child scope starts one level below the sibling fields.
                    self.field(key, value, depth + 1);
                    for (key, value) in fields {
                        self.indent(depth + 1);
                        self.field(key, value, depth + 1);
                    }
                } else {
                    self.0.push('\n');
                }
            }
            Value::Array(array) => {
                self.0.push(' ');
                // A keyless table header is valid only at the document root.
                self.array(array, depth, false);
            }
            _ => {
                self.0.push(' ');
                self.primitive(value);
                self.0.push('\n');
            }
        }
    }

    fn table_header(&mut self, count: usize, keyed: bool, columns: &[Column<'_>]) {
        write!(self.0, "[{count}{}]{{", if keyed { ":" } else { "" }).unwrap();
        self.columns(columns);
        self.0.push_str("}:\n");
    }

    fn columns(&mut self, columns: &[Column<'_>]) {
        for (index, column) in columns.iter().enumerate() {
            if index != 0 {
                self.0.push(',');
            }
            self.key(column.name);
            if !column.children.is_empty() {
                self.0.push('{');
                self.columns(&column.children);
                self.0.push('}');
            }
        }
    }

    fn cells(&mut self, value: &Value, columns: &[Column<'_>]) {
        let object = value
            .as_object()
            .expect("table shape was checked before writing its header");
        for (index, column) in columns.iter().enumerate() {
            if index != 0 {
                self.0.push(',');
            }
            if column.children.is_empty() {
                self.primitive(&object[column.name]);
            } else {
                self.cells(&object[column.name], &column.children);
            }
        }
    }

    fn primitive(&mut self, value: &Value) {
        match value {
            Value::Null => self.0.push_str("null"),
            Value::Bool(value) => self.0.push_str(if *value { "true" } else { "false" }),
            Value::Number(number) => {
                // Integer branches retain all 64 bits. Rust's finite float Display
                // emits a round-tripping decimal without exponent notation.
                if let Some(number) = number.as_i64() {
                    write!(self.0, "{number}").unwrap();
                } else if let Some(number) = number.as_u64() {
                    write!(self.0, "{number}").unwrap();
                } else {
                    let number = number.as_f64().expect("JSON number is a finite float");
                    write!(self.0, "{}", if number == 0.0 { 0.0 } else { number }).unwrap();
                }
            }
            Value::String(value) => {
                if needs_quotes(value) {
                    self.quoted(value);
                } else {
                    self.0.push_str(value);
                }
            }
            Value::Array(_) | Value::Object(_) => {
                unreachable!("only scalar table cells are admitted")
            }
        }
    }

    fn key(&mut self, key: &str) {
        let mut bytes = key.bytes();
        if bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        {
            self.0.push_str(key);
        } else {
            self.quoted(key);
        }
    }

    fn quoted(&mut self, value: &str) {
        self.0.push('"');
        for character in value.chars() {
            match character {
                '\\' => self.0.push_str("\\\\"),
                '"' => self.0.push_str("\\\""),
                '\n' => self.0.push_str("\\n"),
                '\r' => self.0.push_str("\\r"),
                '\t' => self.0.push_str("\\t"),
                '\0'..='\u{1f}' => write!(self.0, "\\u{:04x}", u32::from(character)).unwrap(),
                _ => self.0.push(character),
            }
        }
        self.0.push('"');
    }
}

struct Column<'a> {
    name: &'a str,
    children: Vec<Column<'a>>,
}

fn table_columns<'a>(mut values: impl Iterator<Item = &'a Value>) -> Option<Vec<Column<'a>>> {
    let columns = object_columns(values.next()?.as_object()?)?;
    values
        .all(|value| matches_columns(value, &columns))
        .then_some(columns)
}

fn object_columns(object: &Map<String, Value>) -> Option<Vec<Column<'_>>> {
    if object.is_empty() {
        return None;
    }
    object
        .iter()
        .map(|(name, value)| {
            let children = match value {
                Value::Object(object) => object_columns(object)?,
                Value::Array(_) => return None,
                _ => Vec::new(),
            };
            Some(Column { name, children })
        })
        .collect()
}

fn matches_columns(value: &Value, columns: &[Column<'_>]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == columns.len()
        && columns.iter().all(|column| {
            object.get(column.name).is_some_and(|value| {
                if column.children.is_empty() {
                    is_primitive(value)
                } else {
                    matches_columns(value, &column.children)
                }
            })
        })
}

fn is_primitive(value: &Value) -> bool {
    !matches!(value, Value::Array(_) | Value::Object(_))
}

fn needs_quotes(value: &str) -> bool {
    value.is_empty()
        || value.starts_with([' ', '\t', '-', '#'])
        || value.ends_with([' ', '\t'])
        || matches!(value, "true" | "false" | "null")
        || numeric_like(value)
        || value.chars().any(|character| {
            character <= '\u{1f}'
                || matches!(character, ':' | '"' | '\\' | '[' | ']' | '{' | '}' | ',')
        })
}

fn numeric_like(value: &str) -> bool {
    fn digits(value: &str) -> bool {
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
    }
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, None), |(mantissa, exponent)| {
            (mantissa, Some(exponent))
        });
    let mantissa_valid = mantissa.split_once('.').map_or_else(
        || digits(mantissa),
        |(whole, fraction)| digits(whole) && digits(fraction),
    );
    mantissa_valid
        && exponent
            .is_none_or(|exponent| digits(exponent.strip_prefix(['+', '-']).unwrap_or(exponent)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_values_match_the_pinned_upstream_reference() {
        let fixtures: Value =
            serde_json::from_str(include_str!("../tests/fixtures/toon-reference.json")).unwrap();
        for fixture in fixtures["cases"].as_array().unwrap() {
            assert_eq!(
                encode(&fixture["input"]),
                fixture["toon"].as_str().unwrap(),
                "reference case: {}",
                fixture["name"]
            );
        }
    }

    #[test]
    fn numbers_preserve_all_integer_bits_and_finite_float_values() {
        for integer in [i64::MIN, -9_007_199_254_740_993, 0, i64::MAX] {
            assert_eq!(encode(&Value::from(integer)), integer.to_string());
        }
        for integer in [9_007_199_254_740_993_u64, u64::MAX] {
            assert_eq!(encode(&Value::from(integer)), integer.to_string());
        }
        for number in [
            0.0,
            -0.0,
            1.0,
            -1.25,
            1e-6,
            1e-9,
            1e21,
            f64::MAX,
            f64::MIN_POSITIVE,
            f64::from_bits(1),
        ] {
            let encoded = encode(&Value::from(number));
            assert_eq!(encoded.parse::<f64>().unwrap(), number);
            assert!(!encoded.contains(['e', 'E']));
            if number == 0.0 {
                assert_eq!(encoded, "0");
            }
        }
    }
}
