use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    ParseError, ValidationError, ValidationIssue,
    validation::{
        deserialize_optional_non_null, issue, parse_and_validate, require_unique, result,
    },
};

pub const SERVICE_DOCUMENTS_EXTENSION: &str =
    "urn:aep:ext:aep-foundation:service-documents#v=1.0.0";
pub const MAX_SERVICE_DOCUMENT_BYTES: usize = 1 << 20;
pub const SERVICE_DOCUMENT_TYPES: &[&str] = &[
    "acceptable_use_policy",
    "age_or_parental_consent",
    "ai_data_use_policy",
    "community_guidelines",
    "cookie_policy",
    "data_processing_agreement",
    "data_retention_notice",
    "electronic_signature_consent",
    "privacy_policy",
    "security_policy",
    "subscription_terms",
    "supplemental_terms",
    "terms_of_service",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentEnrollment {
    Required,
    #[serde(rename = "not-required")]
    NotRequired,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DocumentRepresentation {
    pub media_type: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ServiceDocument {
    pub id: String,
    #[serde(rename = "type")]
    pub document_type: String,
    pub title: String,
    pub enrollment: DocumentEnrollment,
    pub representations: Vec<DocumentRepresentation>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PortableDocumentBlock {
    Paragraph {
        text: String,
    },
    Section {
        title: String,
        blocks: Vec<PortableDocumentBlock>,
    },
    BulletedList {
        items: Vec<String>,
    },
    NumberedList {
        items: Vec<String>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PortableServiceDocument {
    pub format: String,
    pub version: String,
    pub id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub summary: Option<Vec<PortableDocumentBlock>>,
    pub content: Vec<PortableDocumentBlock>,
}

pub(crate) fn validate_document_ids(ids: &[String], path: &str, issues: &mut Vec<ValidationIssue>) {
    if ids.len() > 7 || ids.iter().any(|id| !valid_id(id)) {
        issues.push(issue(
            path,
            "Expected at most seven IDs of 1 to 32 ASCII identifier characters.",
        ));
    }
    require_unique(ids, path, issues);
}

fn valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn validate_service_document(document: &ServiceDocument) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    if !valid_id(&document.id) {
        issues.push(issue(
            "$.id",
            "Expected a document ID of 1 to 32 ASCII identifier characters.",
        ));
    }
    if !(1..=64).contains(&document.document_type.len())
        || !document
            .document_type
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
        || !document
            .document_type
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        issues.push(issue("$.type", "Expected a lowercase document type."));
    }
    bounded_text(&document.title, 256, "$.title", &mut issues);
    let mut media = HashSet::new();
    if !(1..=8).contains(&document.representations.len()) {
        issues.push(issue(
            "$.representations",
            "Expected 1 to 8 representations.",
        ));
    }
    for representation in &document.representations {
        if !media.insert(representation.media_type.as_str())
            || !valid_media_type(&representation.media_type)
        {
            issues.push(issue(
                "$.representations",
                "Expected distinct lowercase media types without parameters.",
            ));
        }
        if !valid_document_url(&representation.url) {
            issues.push(issue("$.representations", "Expected an absolute HTTPS URL or literal-loopback HTTP URL, without user information, at most 2048 ASCII characters."));
        }
    }
    if !media.contains("text/html") {
        issues.push(issue(
            "$.representations",
            "Expected an HTML representation.",
        ));
    }
    result("Service Document", issues)
}

fn valid_media_type(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    [kind, subtype].into_iter().all(|part| {
        part.as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$&^_.+-".contains(&b))
    })
}

fn valid_document_url(value: &str) -> bool {
    if value.len() > 2048
        || !value.is_ascii()
        || value.bytes().any(|b| b <= 32 || b == 127 || b == b'\\')
    {
        return false;
    }
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.host_str().is_none() {
        return false;
    }
    let literal_host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map(|(host, _)| format!("{host}]"))
            .unwrap_or_default()
    } else {
        authority
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(literal_host.as_str(), "localhost" | "127.0.0.1" | "[::1]"))
}

pub fn parse_portable_service_document(
    data: &[u8],
    expected_id: &str,
) -> Result<PortableServiceDocument, ParseError> {
    if data.len() > MAX_SERVICE_DOCUMENT_BYTES {
        return Err(ValidationError {
            document_type: "portable Service Document".into(),
            issues: vec![issue("$", "Document exceeds one mebibyte.")],
        }
        .into());
    }
    parse_and_validate(
        data,
        "portable Service Document",
        |document: &PortableServiceDocument| {
            validate_portable_service_document(document)?;
            result(
                "portable Service Document",
                if document.id == expected_id {
                    vec![]
                } else {
                    vec![issue(
                        "$.id",
                        "Document ID does not match the selected descriptor.",
                    )]
                },
            )
        },
    )
}

pub fn validate_portable_service_document(
    document: &PortableServiceDocument,
) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    if document.format != "aep-service-document"
        || document.version != "1.0"
        || !valid_id(&document.id)
    {
        issues.push(issue("$", "Unsupported document format, version, or ID."));
    }
    if document.content.is_empty() || document.summary.as_ref().is_some_and(Vec::is_empty) {
        issues.push(issue(
            "$",
            "Content and supplied summary must contain blocks.",
        ));
    }
    let mut pending: Vec<_> = document
        .content
        .iter()
        .chain(document.summary.iter().flatten())
        .map(|block| (block, 0))
        .collect();
    let mut count = 0;
    while let Some((block, depth)) = pending.pop() {
        count += 1;
        if count > 1024 {
            issues.push(issue("$", "Expected at most 1024 total blocks."));
            break;
        }
        match block {
            PortableDocumentBlock::Paragraph { text } => {
                bounded_text(text, 16384, "$.text", &mut issues)
            }
            PortableDocumentBlock::Section { title, blocks } => {
                bounded_text(title, 256, "$.title", &mut issues);
                if depth >= 8 || blocks.is_empty() {
                    issues.push(issue(
                        "$.blocks",
                        "Expected nonempty sections at most eight levels deep.",
                    ));
                }
                pending.extend(blocks.iter().map(|block| (block, depth + 1)));
            }
            PortableDocumentBlock::BulletedList { items }
            | PortableDocumentBlock::NumberedList { items } => {
                if !(1..=128).contains(&items.len()) {
                    issues.push(issue("$.items", "Expected 1 to 128 list items."));
                }
                for text in items {
                    bounded_text(text, 16384, "$.items", &mut issues);
                }
            }
        }
    }
    result("portable Service Document", issues)
}

fn bounded_text(value: &str, maximum: usize, path: &str, issues: &mut Vec<ValidationIssue>) {
    if value.is_empty() || value.chars().count() > maximum {
        issues.push(issue(
            path,
            format!("Expected 1 to {maximum} Unicode scalar values."),
        ));
    }
}
