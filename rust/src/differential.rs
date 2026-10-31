//! Python's own answers for thousands of inputs (tests/fixtures/python-differential.json,
//! from conformance/make_differential.py), checked against this port.

use crate::pyjson::{self, Value};

fn table(name: &str) -> Vec<Value> {
    let raw = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/python-differential.json")).unwrap();
    let Value::Object(doc) = pyjson::loads(&raw).unwrap() else { panic!() };
    doc[name].as_array().unwrap().clone()
}

fn pair(row: &Value) -> (String, Option<String>) {
    let row = row.as_array().unwrap();
    (row[0].as_str().unwrap().to_string(), row[1].as_str().map(str::to_string))
}

#[test]
fn floats_print_exactly_as_python_repr() {
    let rows = table("floats");
    assert!(rows.len() > 4000);
    for row in &rows {
        let (bits, want) = pair(row);
        let x = f64::from_bits(u64::from_str_radix(&bits, 16).unwrap());
        assert_eq!(pyjson::canonical(&Value::Float(x)), want.unwrap(), "{bits}");
    }
}

#[test]
fn timestamps_parse_exactly_as_fromisoformat() {
    let rows = table("timestamps");
    assert!(rows.len() > 3000);
    for row in &rows {
        let (text, want) = pair(row);
        let got = crate::isotime::parse_fromisoformat(&text).map(|us| us.to_string());
        assert_eq!(got, want, "{text:?}");
    }
}

#[test]
fn documents_load_and_canonicalise_exactly_as_python() {
    let rows = table("documents");
    assert!(rows.len() > 2000);
    for row in &rows {
        let (text, want) = pair(row);
        let got = pyjson::loads(text.as_bytes()).ok().map(|v| pyjson::canonical(&v));
        assert_eq!(got, want, "{text:?}");
    }
}
