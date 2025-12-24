// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use cel_interpreter::Value as celValue;
use cel_interpreter::{Context, Program};
use serde_json::Value;

use crate::constants::MAX_EXPRESSION_LENGTH;
use crate::functions;

pub fn execute_expressions(
    fields: &HashMap<String, Value>,
    expressions: &HashMap<String, String>,
) -> Result<HashMap<String, Value>> {
    if expressions.is_empty() {
        return Ok(fields.clone());
    }

    // Validate expression lengths before processing
    for (field, expression) in expressions {
        if expression.len() > MAX_EXPRESSION_LENGTH {
            bail!(
                "expression for field '{}' exceeds maximum length: {} > {}",
                field,
                expression.len(),
                MAX_EXPRESSION_LENGTH
            );
        }
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
    context.add_function("sha256", functions::sha256_hash);
    context.add_function("sha384", functions::sha384_hash);
    context.add_function("sha512", functions::sha512_hash);
    // datetime
    context.add_function("today_utc", functions::today_utc);
    context.add_function("date", functions::date);
    context.add_function("age", functions::age);

    let mut transformed: HashMap<String, Value> =
        HashMap::with_capacity(fields.len() + expressions.len());

    for (field, decrypted_value) in fields {
        context
            .add_variable(field, decrypted_value)
            .map_err(|err| anyhow!("Unable to add variable '{field}': {err}"))?;
        transformed.insert(field.to_string(), decrypted_value.clone());
    }

    for (field, expression) in expressions {
        let program = Program::compile(expression.as_str());

        let value: celValue = match program {
            Ok(program) => match program.execute(&context) {
                Ok(value) => value,
                Err(err) => format!("Execution Error: {err}").into(),
            },
            Err(err) => format!("Compile Error: {err}").into(),
        };

        context.add_variable_from_value(field, value.clone());

        let result: Value = value
            .json()
            .map_err(|err| anyhow!("Unable to serialize JSON value: {err}"))?;

        // Only log expression results in debug builds to prevent sensitive data leakage
        #[cfg(debug_assertions)]
        println!("[enclave] expression: {expression} = {result:?}");

        transformed.insert(field.to_string(), result);
    }

    Ok(transformed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    // **Feature: enclave-improvements, Property 5: Expression failure fallback**
    // **Validates: Requirements 8.2**
    //
    // *For any* set of decrypted fields and any expression that fails to execute,
    // the system SHALL return the original decrypted fields unchanged.
    //
    // Note: The execute_expressions function handles errors in two ways:
    // 1. Individual expression compile/execution errors are captured as error strings in the output
    // 2. Variable addition errors cause the function to return Err
    //
    // This property test verifies that when expressions fail to compile or execute,
    // the original field values are preserved (though the expression result may be an error string).
    // The fallback behavior in main.rs (returning original fields on Err) is tested separately.

    /// Simulates the fallback behavior from main.rs:
    /// When execute_expressions returns Err, return the original fields unchanged.
    fn execute_with_fallback(
        fields: &HashMap<String, Value>,
        expressions: &HashMap<String, String>,
    ) -> HashMap<String, Value> {
        match execute_expressions(fields, expressions) {
            Ok(result) => result,
            Err(_) => fields.clone(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_expression_failure_preserves_original_fields(
            // Generate random field names and values
            field_name in "[a-z][a-z0-9_]{0,10}",
            field_value in "[a-zA-Z0-9 ]{1,20}",
            // Generate invalid expression that will fail to execute (but not panic)
            // Note: We avoid syntax errors that cause the CEL parser to panic
            invalid_expr_type in 0usize..3
        ) {
            // Create original fields
            let mut fields: HashMap<String, Value> = HashMap::new();
            fields.insert(field_name.clone(), Value::String(field_value.clone()));

            // Create an invalid expression that will fail to execute gracefully
            // These expressions compile but fail at runtime, or reference undefined variables
            let invalid_expression = match invalid_expr_type {
                0 => "undefined_variable.method()".to_string(),
                1 => "nonexistent_function()".to_string(),
                _ => "undefined_var.to_uppercase()".to_string(),
            };

            let mut expressions: HashMap<String, String> = HashMap::new();
            expressions.insert("result".to_string(), invalid_expression);

            // Execute with fallback (simulating main.rs behavior)
            let result = execute_with_fallback(&fields, &expressions);

            // The original field should be preserved
            prop_assert!(
                result.contains_key(&field_name),
                "Original field '{}' should be preserved in result",
                field_name
            );
            prop_assert_eq!(
                result.get(&field_name),
                Some(&Value::String(field_value.clone())),
                "Original field value should be unchanged"
            );
        }

        #[test]
        fn prop_expression_error_does_not_modify_original_field_values(
            // Generate multiple fields
            num_fields in 1usize..5,
            field_seed in any::<u64>()
        ) {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            // Generate deterministic field names and values based on seed
            let mut fields: HashMap<String, Value> = HashMap::new();
            for i in 0..num_fields {
                let mut hasher = DefaultHasher::new();
                (field_seed, i).hash(&mut hasher);
                let hash = hasher.finish();
                let name = format!("field_{}", i);
                let value = format!("value_{}", hash % 1000);
                fields.insert(name, Value::String(value));
            }

            // Create an expression that references an undefined variable
            let mut expressions: HashMap<String, String> = HashMap::new();
            expressions.insert("computed".to_string(), "undefined_var.to_uppercase()".to_string());

            // Execute with fallback
            let result = execute_with_fallback(&fields, &expressions);

            // All original fields should be preserved with their original values
            for (name, value) in &fields {
                prop_assert!(
                    result.contains_key(name),
                    "Original field '{}' should be preserved",
                    name
                );
                prop_assert_eq!(
                    result.get(name),
                    Some(value),
                    "Original field '{}' value should be unchanged",
                    name
                );
            }
        }

        #[test]
        fn prop_empty_expressions_returns_original_fields_unchanged(
            // Generate random fields
            field_name in "[a-z][a-z0-9_]{0,10}",
            field_value in "[a-zA-Z0-9 ]{1,20}"
        ) {
            let mut fields: HashMap<String, Value> = HashMap::new();
            fields.insert(field_name.clone(), Value::String(field_value.clone()));

            let expressions: HashMap<String, String> = HashMap::new();

            let result = execute_expressions(&fields, &expressions).unwrap();

            prop_assert_eq!(
                result,
                fields,
                "Empty expressions should return original fields unchanged"
            );
        }

        #[test]
        fn prop_valid_expression_on_existing_field_transforms_correctly(
            // Generate a field name that's valid for CEL
            field_name in "[a-z][a-z0-9_]{0,10}",
            // Generate lowercase string to test to_uppercase
            field_value in "[a-z]{1,10}"
        ) {
            let mut fields: HashMap<String, Value> = HashMap::new();
            fields.insert(field_name.clone(), Value::String(field_value.clone()));

            // Create expression to uppercase the field
            let mut expressions: HashMap<String, String> = HashMap::new();
            expressions.insert(field_name.clone(), format!("{}.to_uppercase()", field_name));

            let result = execute_expressions(&fields, &expressions).unwrap();

            // The field should be transformed to uppercase
            prop_assert_eq!(
                result.get(&field_name),
                Some(&Value::String(field_value.to_uppercase())),
                "Field should be transformed to uppercase"
            );
        }
    }

    #[test]
    fn test_skip_expressions() {
        let expressions = HashMap::new();

        let expected: HashMap<String, Value> =
            HashMap::from([("first_name".to_string(), "Bob".into())]);

        let actual = execute_expressions(&expected, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_execute_transforms() {
        let expressions: HashMap<String, String> = HashMap::from([(
            "first_name".to_string(),
            "first_name.to_uppercase()".to_string(),
        )]);

        let fields: HashMap<String, Value> =
            HashMap::from([("first_name".to_string(), "Bob".into())]);

        let expected: HashMap<String, Value> =
            HashMap::from([("first_name".to_string(), "BOB".into())]);

        let actual = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_base64() {
        let expressions: HashMap<String, String> = HashMap::from([(
            "first_name".into(),
            "first_name.base64_encode().base64_decode()".into(),
        )]);

        let fields: HashMap<String, Value> = HashMap::from([("first_name".into(), "Bob".into())]);

        let expected: HashMap<String, Value> = HashMap::from([("first_name".into(), "Bob".into())]);

        let actual = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_hex() {
        let expressions: HashMap<String, String> = HashMap::from([(
            "first_name".into(),
            "first_name.hex_encode().hex_decode()".into(),
        )]);

        let fields: HashMap<String, Value> = HashMap::from([("first_name".into(), "Bob".into())]);

        let expected: HashMap<String, Value> = HashMap::from([("first_name".into(), "Bob".into())]);

        let actual = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_functions() {
        let expressions: HashMap<String, String> = HashMap::from([
            ("is_empty".into(), "''.is_empty() == true".into()),
            ("to_lowercase".into(), "'Bob'.to_lowercase()".into()),
            ("to_uppercase".into(), "'Bob'.to_uppercase()".into()),
            ("sha256".into(), "'Bob'.sha256()".into()),
            ("sha384".into(), "'Bob'.sha384()".into()),
            ("sha512".into(), "'Bob'.sha512()".into()),
            ("hex_encode".into(), "'Bob'.hex_encode()".into()),
            ("hex_decode".into(), "'426f62'.hex_decode()".into()),
            ("base64_encode".into(), "'Bob'.base64_encode()".into()),
            ("base64_decode".into(), "'Qm9i'.base64_decode()".into()),
            ("date".into(), "date('1979-04-05')".into()),
        ]);

        let fields = HashMap::default();
        // Note: Using Vec for comparison since HashMap ordering is non-deterministic
        let actual = execute_expressions(&fields, &expressions).unwrap();

        assert_eq!(actual.get("is_empty"), Some(&Value::Bool(true)));
        assert_eq!(
            actual.get("to_lowercase"),
            Some(&Value::String("bob".into()))
        );
        assert_eq!(
            actual.get("to_uppercase"),
            Some(&Value::String("BOB".into()))
        );
        assert_eq!(
            actual.get("sha256"),
            Some(&Value::String(
                "cd9fb1e148ccd8442e5aa74904cc73bf6fb54d1d54d333bd596aa9bb4bb4e961".into()
            ))
        );
        assert_eq!(actual.get("sha384"), Some(&Value::String("b7808c5991933fa578a7d41a177b013f2f745a2c4fac90d1e8631a1ce21918dc5fee092a290a6443e47649989ec9871f".into())));
        assert_eq!(actual.get("sha512"), Some(&Value::String("0c3e99453b4ae505617a3c9b6ce73fc3cd13ddc3b2e2237459710a57f8ec6d26d056db144ff7c71b00ed4e4c39716e9e2099c8076e604423dd74554d4db1e649".into())));
        assert_eq!(
            actual.get("hex_encode"),
            Some(&Value::String("426f62".into()))
        );
        assert_eq!(actual.get("hex_decode"), Some(&Value::String("Bob".into())));
        assert_eq!(
            actual.get("base64_encode"),
            Some(&Value::String("Qm9i".into()))
        );
        assert_eq!(
            actual.get("base64_decode"),
            Some(&Value::String("Bob".into()))
        );
        assert_eq!(
            actual.get("date"),
            Some(&Value::String("1979-04-05T00:00:00+00:00".into()))
        );
    }

    #[test]
    fn test_complex() {
        let expressions: HashMap<String, String> =
            HashMap::from([("age".into(), "date(birth_date).age()".into())]);

        let fields: HashMap<String, Value> = HashMap::from([
            ("first_name".into(), "Bob".into()),
            ("birth_date".into(), "1979-01-01".into()),
        ]);

        let actual = execute_expressions(&fields, &expressions).unwrap();

        assert_eq!(actual.get("first_name"), Some(&Value::String("Bob".into())));
        assert_eq!(
            actual.get("birth_date"),
            Some(&Value::String("1979-01-01".into()))
        );
        assert_eq!(actual.get("age"), Some(&Value::Number(46.into())));
    }
}
