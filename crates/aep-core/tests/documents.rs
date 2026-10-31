use aep_core::*;
use serde_json::{Value, json};

fn descriptor() -> ServiceDocument {
    serde_json::from_value(json!({
        "id":"terms", "type":"custom_notice", "title":"Terms", "enrollment":"required",
        "representations":[{"media_type":"text/html","url":"https://example.com/terms"}],
        "future":true
    }))
    .unwrap()
}

fn portable(content: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"format":"aep-service-document","version":"1.0",
        "id":"terms","content":content,"future":true}))
    .unwrap()
}

#[test]
fn enrollment_requirement_has_exact_wire_values() {
    for enrollment in ["required", "not-required"] {
        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["enrollment"] = json!(enrollment);
        let document: ServiceDocument = serde_json::from_value(value).unwrap();
        validate_service_document(&document).unwrap();
        assert_eq!(
            serde_json::to_value(document).unwrap()["enrollment"],
            enrollment
        );
    }
    for enrollment in ["not_required", "optional"] {
        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["enrollment"] = json!(enrollment);
        assert!(serde_json::from_value::<ServiceDocument>(value).is_err());
    }
}

#[test]
fn descriptor_enforces_bounds_without_restricting_document_types_or_https_destinations() {
    let mut document = descriptor();
    validate_service_document(&document).unwrap();
    for url in [
        "https://192.168.1.10/doc",
        "https://localhost/doc",
        "http://localhost:8080/doc",
        "http://127.0.0.1/doc",
        "http://[::1]/doc",
    ] {
        document.representations[0].url = url.into();
        validate_service_document(&document).unwrap();
    }
    for url in [
        "http://example.com/doc",
        "http://127.1/doc",
        "http://2130706433/doc",
        "http://localhost.example/doc",
        "https://u:p@example.com/doc",
        "https:///example.com/doc",
        "https://example.com\\doc",
        "/doc",
        "https://example.com/é",
        "https://example.com/\n",
        "https://[",
        "file://localhost/doc",
    ] {
        document.representations[0].url = url.into();
        assert!(validate_service_document(&document).is_err(), "{url}");
    }
    document = descriptor();
    for id in ["", "_terms", "térms", "terms\n", &"a".repeat(33)] {
        document.id = id.into();
        assert!(validate_service_document(&document).is_err());
    }
    document = descriptor();
    document.title = "é".repeat(256);
    validate_service_document(&document).unwrap();
    document.title.push('é');
    assert!(validate_service_document(&document).is_err());
    for kind in ["", "Terms", "1terms", "terms-of-service", &"a".repeat(65)] {
        document = descriptor();
        document.document_type = kind.into();
        assert!(validate_service_document(&document).is_err());
    }
    for media in [
        "Text/html",
        "text/html; charset=utf-8",
        "text/",
        "text//html",
        "html",
    ] {
        document = descriptor();
        document.representations[0].media_type = media.into();
        assert!(validate_service_document(&document).is_err());
    }
    document = descriptor();
    document
        .representations
        .push(document.representations[0].clone());
    assert!(validate_service_document(&document).is_err());
    document.representations.clear();
    assert!(validate_service_document(&document).is_err());
}

#[test]
fn portable_content_is_complete_bounded_and_forward_compatible() {
    let blocks = json!([{"type":"section","title":"Title","blocks":[
        {"type":"paragraph","text":"Full text","future":true},
        {"type":"bulleted_list","items":["One"]},
        {"type":"numbered_list","items":["Two"]}]}]);
    let body = portable(blocks);
    parse_portable_service_document(&body, "terms").unwrap();
    assert!(parse_portable_service_document(&body, "Terms").is_err());
    for blocks in [
        json!([]),
        json!([{"type":"unknown","text":"Text"}]),
        json!([{"type":"paragraph","text":1}]),
        json!([{"type":"paragraph","text":""}]),
        json!([{"type":"section","title":"Title","blocks":[]}]),
        json!([{"type":"bulleted_list","items":[]}]),
        json!([{"type":"numbered_list","items":[""]}]),
    ] {
        assert!(parse_portable_service_document(&portable(blocks), "terms").is_err());
    }
    for length in [16384, 16385] {
        let body = portable(json!([{"type":"paragraph","text":"é".repeat(length)}]));
        assert_eq!(
            parse_portable_service_document(&body, "terms").is_ok(),
            length == 16384
        );
    }
    for count in [128, 129] {
        let body = portable(json!([{"type":"numbered_list","items":vec!["x";count]}]));
        assert_eq!(
            parse_portable_service_document(&body, "terms").is_ok(),
            count == 128
        );
    }
    let mut nested = json!({"type":"paragraph","text":"x"});
    for depth in 1..=9 {
        nested = json!({"type":"section","title":"x","blocks":[nested]});
        assert_eq!(
            parse_portable_service_document(&portable(json!([nested.clone()])), "terms").is_ok(),
            depth <= 8
        );
    }
    for count in [1023, 1024] {
        let mut value: Value = serde_json::from_slice(&portable(json!(vec![
            json!({"type":"paragraph","text":"x"});
            count
        ])))
        .unwrap();
        value["summary"] = json!([{"type":"paragraph","text":"Summary"}]);
        assert_eq!(
            parse_portable_service_document(&serde_json::to_vec(&value).unwrap(), "terms").is_ok(),
            count == 1023
        );
    }
    for (field, value) in [
        ("summary", json!(null)),
        ("summary", json!([])),
        ("format", json!("other")),
        ("version", json!("2.0")),
    ] {
        let mut value_body: Value = serde_json::from_slice(&body).unwrap();
        value_body[field] = value;
        assert!(
            parse_portable_service_document(&serde_json::to_vec(&value_body).unwrap(), "terms")
                .is_err()
        );
    }
    assert!(
        parse_portable_service_document(&vec![b' '; MAX_SERVICE_DOCUMENT_BYTES + 1], "terms")
            .is_err()
    );
}

#[test]
fn acknowledgement_and_requirement_fields_preserve_omission_and_reject_invalid_declarations() {
    let request = json!({"agent_did":"did:example:agent"});
    assert_eq!(
        parse_enroll_request(&serde_json::to_vec(&request).unwrap())
            .unwrap()
            .acknowledged_document_ids,
        None
    );
    for ids in [
        json!([]),
        json!(["Terms", "terms"]),
        json!(
            (0..7)
                .map(|i| format!("{i}{}", "a".repeat(31)))
                .collect::<Vec<_>>()
        ),
    ] {
        let mut value = request.clone();
        value["acknowledged_document_ids"] = ids.clone();
        let parsed = parse_enroll_request(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["acknowledged_document_ids"],
            ids
        );
        parse_enroll_response(
            &serde_json::to_vec(&json!({"status":"active","acknowledged_document_ids":ids}))
                .unwrap(),
        )
        .unwrap();
    }
    for ids in [
        json!(null),
        json!(["terms", "terms"]),
        json!(["bad id"]),
        json!([1]),
        json!(["a", "b", "c", "d", "e", "f", "g", "h"]),
    ] {
        let mut value = request.clone();
        value["acknowledged_document_ids"] = ids;
        assert!(parse_enroll_request(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let problem = json!({"type":"urn:aep:error:requirements_unmet","title":"Requirements unmet","status":422,
        "code":"requirements_unmet","requirements_pending":["contact.email","service_documents"],"required_document_ids":["terms"]});
    parse_problem_details(&serde_json::to_vec(&problem).unwrap()).unwrap();
    for (field, value) in [
        ("required_document_ids", json!([])),
        ("required_document_ids", json!(null)),
        ("requirements_pending", json!(["contact.email"])),
        ("status", json!(401)),
        ("code", json!("not_recognized")),
    ] {
        let mut invalid = problem.clone();
        invalid[field] = value;
        assert!(parse_problem_details(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
}
