use std::{collections::HashSet, hash::Hash};

use serde::de::DeserializeOwned;

use crate::{ParseError, ValidationError, ValidationIssue};

pub(crate) fn parse_and_validate<T>(
    data: &[u8],
    document_type: &str,
    validate: impl FnOnce(&T) -> Result<(), ValidationError>,
) -> Result<T, ParseError>
where
    T: DeserializeOwned,
{
    let mut deserializer = serde_json::Deserializer::from_slice(data);
    let value = match serde_path_to_error::deserialize::<_, T>(&mut deserializer) {
        Ok(value) => value,
        Err(error) if error.inner().is_syntax() || error.inner().is_eof() => {
            return Err(ParseError::Json {
                document_type: document_type.to_owned(),
                source: error.into_inner(),
            });
        }
        Err(error) => {
            return Err(ValidationError {
                document_type: document_type.to_owned(),
                issues: vec![ValidationIssue {
                    path: json_path(&error.path().to_string()),
                    message: error.inner().to_string(),
                }],
            }
            .into());
        }
    };
    deserializer.end().map_err(|source| ParseError::Json {
        document_type: document_type.to_owned(),
        source,
    })?;
    validate(&value)?;
    Ok(value)
}

pub(crate) fn deserialize_optional_non_null<'de, D, T>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub(crate) fn result(
    document_type: &str,
    issues: Vec<ValidationIssue>,
) -> Result<(), ValidationError> {
    if issues.is_empty() {
        Ok(())
    } else {
        Err(ValidationError {
            document_type: document_type.to_owned(),
            issues,
        })
    }
}

pub(crate) fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

pub(crate) fn require_non_empty(value: &str, path: &str, issues: &mut Vec<ValidationIssue>) {
    if value.is_empty() {
        issues.push(issue(path, "Expected a non-empty string."));
    }
}

pub(crate) fn validate_optional_non_empty(
    value: Option<&str>,
    path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    if value.is_some_and(str::is_empty) {
        issues.push(issue(path, "Expected a non-empty string."));
    }
}

pub(crate) fn require_unique<T>(values: &[T], path: &str, issues: &mut Vec<ValidationIssue>)
where
    T: Eq + Hash,
{
    let mut seen = HashSet::with_capacity(values.len());
    if values.iter().any(|value| !seen.insert(value)) {
        issues.push(issue(path, "Expected unique items."));
    }
}

pub(crate) fn validate_non_empty_strings(
    values: &[String],
    path: &str,
    require_items: bool,
    issues: &mut Vec<ValidationIssue>,
) {
    if require_items && values.is_empty() {
        issues.push(issue(path, "Expected at least one item."));
    }
    for (index, value) in values.iter().enumerate() {
        require_non_empty(value, &format!("{path}[{index}]"), issues);
    }
    require_unique(values, path, issues);
}

fn json_path(path: &str) -> String {
    if path.is_empty() {
        "$".to_owned()
    } else if path.starts_with('[') {
        format!("${path}")
    } else {
        format!("$.{path}")
    }
}
