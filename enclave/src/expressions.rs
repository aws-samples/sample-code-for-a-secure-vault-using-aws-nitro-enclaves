// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use cel_interpreter::Value as celValue;
use cel_interpreter::{Context, Program};
use serde_json::Value;

use crate::functions;

pub fn execute_expressions(
    fields: &BTreeMap<String, Value>,
    expressions: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Value>> {
    if expressions.is_empty() {
        return Ok(fields.clone());
    }

    let mut context = Context::default();
    // strings
    context.add_function("is_empty", functions::is_empty);
    context.add_function("to_lowercase", functions::to_lowercase);
    context.add_function("to_uppercase", functions::to_uppercase);
    // base64
    context.add_function("base64_encode", functions::base64_encode);
    context.add_function("base64_decode", functions::base64_decode);
    // hex
    context.add_function("hex_encode", functions::hex_encode);
    context.add_function("hex_decode", functions::hex_decode);
    // hmac
    context.add_function("hmac_sha256", functions::hmac_sha256);
    context.add_function("hmac_sha384", functions::hmac_sha384);
    context.add_function("hmac_sha512", functions::hmac_sha512);
    // datetime
    context.add_function("today_utc", functions::today_utc);
    context.add_function("date", functions::date);
    context.add_function("age", functions::age);

    let mut transformed: BTreeMap<String, Value> = BTreeMap::new();

    for (field, decrypted_value) in fields {
        context
            .add_variable(field, decrypted_value)
            .map_err(|err| anyhow!("Unable to add variable '{}': {}", field, err))?;
        transformed.insert(field.to_string(), decrypted_value.clone());
    }

    for (field, expression) in expressions {
        let program = Program::compile(expression.as_str());

        let value: celValue = match program {
            Ok(program) => match program.execute(&context) {
                Ok(value) => value,
                Err(err) => format!("Execution Error: {}", err).into(),
            },
            Err(err) => format!("Compile Error: {}", err).into(),
        };

        context.add_variable_from_value(field, value.clone());

        let result: Value = serde_json::to_value(value)
            .map_err(|err| anyhow!("Unable to serialize JSON value: {}", err))?;
        println!("[enclave] expression: {} = {:?}", expression, result);

        transformed.insert(field.to_string(), result);
    }

    Ok(transformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_skip_expressions() {
        let expressions = BTreeMap::new();

        let expected: BTreeMap<String, Value> =
            BTreeMap::from([("first_name".to_string(), "Bob".into())]);

        let actual = execute_expressions(&expected, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_execute_transforms() {
        let expressions: BTreeMap<String, String> = BTreeMap::from([(
            "first_name".to_string(),
            "first_name.to_uppercase()".to_string(),
        )]);

        let fields: BTreeMap<String, Value> =
            BTreeMap::from([("first_name".to_string(), "Bob".into())]);

        let expected: BTreeMap<String, Value> =
            BTreeMap::from([("first_name".to_string(), "BOB".into())]);

        let actual = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_base64() {
        let expressions: BTreeMap<String, String> = BTreeMap::from([(
            "first_name".into(),
            "first_name.base64_encode().base64_decode()".into(),
        )]);

        let fields: BTreeMap<String, Value> = BTreeMap::from([("first_name".into(), "Bob".into())]);

        let expected: BTreeMap<String, Value> =
            BTreeMap::from([("first_name".into(), "Bob".into())]);

        let actual = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_hex() {
        let expressions: BTreeMap<String, String> = BTreeMap::from([(
            "first_name".into(),
            "first_name.hex_encode().hex_decode()".into(),
        )]);

        let fields: BTreeMap<String, Value> = BTreeMap::from([("first_name".into(), "Bob".into())]);

        let expected: BTreeMap<String, Value> =
            BTreeMap::from([("first_name".into(), "Bob".into())]);

        let actual = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_functions() {
        let expressions: BTreeMap<String, String> = BTreeMap::from([
            ("is_empty".into(), "''.is_empty() == true".into()),
            ("to_lowercase".into(), "'Bob'.to_lowercase()".into()),
            ("to_uppercase".into(), "'Bob'.to_uppercase()".into()),
            ("hmac_sha256".into(), "'Bob'.hmac_sha256()".into()),
            ("hmac_sha384".into(), "'Bob'.hmac_sha384()".into()),
            ("hmac_sha512".into(), "'Bob'.hmac_sha512()".into()),
            ("hex_encode".into(), "'Bob'.hex_encode()".into()),
            ("hex_decode".into(), "'426f62'.hex_decode()".into()),
            ("base64_encode".into(), "'Bob'.base64_encode()".into()),
            ("base64_decode".into(), "'Qm9i'.base64_decode()".into()),
            ("date".into(), "date('1979-04-05')".into()),
        ]);

        let fields = BTreeMap::default();
        let expected: BTreeMap<String, Value> =
            BTreeMap::from([
                ("is_empty".into(), true.into()),
                ("to_lowercase".into(), "bob".into()),
                ("to_uppercase".into(), "BOB".into()),
                ("hmac_sha256".into(), "cd9fb1e148ccd8442e5aa74904cc73bf6fb54d1d54d333bd596aa9bb4bb4e961".into()),
                ("hmac_sha384".into(), "b7808c5991933fa578a7d41a177b013f2f745a2c4fac90d1e8631a1ce21918dc5fee092a290a6443e47649989ec9871f".into()),
                ("hmac_sha512".into(), "0c3e99453b4ae505617a3c9b6ce73fc3cd13ddc3b2e2237459710a57f8ec6d26d056db144ff7c71b00ed4e4c39716e9e2099c8076e604423dd74554d4db1e649".into()),
                ("hex_encode".into(), "426f62".into()),
                ("hex_decode".into(), "Bob".into()),
                ("base64_encode".into(), "Qm9i".into()),
                ("base64_decode".into(), "Bob".into()),
                ("date".into(), "1979-04-05T00:00:00+00:00".into()),
            ]);

        let actual = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_complex() {
        let expressions: BTreeMap<String, String> =
            BTreeMap::from([("age".into(), "date(birth_date).age()".into())]);

        let fields: BTreeMap<String, Value> = BTreeMap::from([
            ("first_name".into(), "Bob".into()),
            ("birth_date".into(), "1979-01-01".into()),
        ]);

        let expected: BTreeMap<String, Value> = BTreeMap::from([
            ("first_name".into(), "Bob".into()),
            ("birth_date".into(), "1979-01-01".into()),
            ("age".into(), 45.into()),
        ]);

        let actual = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }
}
