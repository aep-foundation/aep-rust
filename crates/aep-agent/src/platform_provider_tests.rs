use super::*;
use time::format_description::well_known::Rfc3339;

fn discovery() -> PlatformDiscovery {
    serde_json::from_value(serde_json::json!({
        "aep_version": "1.0",
        "endpoints": {
            "lifecycle": "/v1/aep/agent-identities/{agent_identity_id}",
            "list": "/v1/aep/agent-identities",
            "provision": "/v1/aep/agent-identities",
            "sign": "/v1/aep/agent-identities/{agent_identity_id}/sign"
        },
        "http": {"endpoint_base": "/v1/aep"},
        "identity": {
            "did_methods": ["did:web"],
            "did_url_template": "https://platform.example/agents/{agent_did_id}/did.json"
        },
        "platform": {"hosted_verification": false, "name": "Platform"},
        "signing": {"algorithms": ["ES256"], "default_lifetime_seconds": "300"}
    }))
    .expect("Discovery")
}

fn identity() -> PlatformAgentIdentity {
    serde_json::from_value(serde_json::json!({
        "agent_did": "did:web:platform.example:agents:one",
        "agent_identity_id": "identity-one",
        "created_at": "2026-08-31T12:00:00Z",
        "did_document_url": "https://platform.example/agents/one/did.json",
        "key_id": "did:web:platform.example:agents:one",
        "service_did": "did:web:service.example",
        "signing_algorithms": ["ES256"],
        "status": "active",
        "updated_at": "2026-08-31T12:00:00Z"
    }))
    .expect("identity")
}

#[test]
fn validates_platform_urls_and_discovery_contract() {
    assert!(platform_url("https://platform.example/path", false).is_ok());
    assert!(platform_url("http://localhost:8080", false).is_err());
    assert!(platform_url("http://localhost:8080", true).is_ok());
    assert!(platform_url("https://user@platform.example", false).is_err());

    let mut document = discovery();
    assert!(validate_discovery(&document, false).is_ok());
    document.aep_version = "2.0".to_owned();
    assert!(validate_discovery(&document, false).is_err());
    document = discovery();
    document.endpoints.hosted_verification = Some("/v1/aep/verifications".to_owned());
    assert!(validate_discovery(&document, false).is_err());
    document.platform.hosted_verification = true;
    assert!(validate_discovery(&document, false).is_ok());
    document.endpoints.hosted_verification = Some("https://other.example/verify".to_owned());
    assert!(validate_discovery(&document, false).is_err());
    document = discovery();
    document.identity.did_url_template = "not a URL/{agent_did_id}".to_owned();
    assert!(validate_discovery(&document, false).is_err());
    document.identity.did_url_template =
        "http://platform.example/agents/{agent_did_id}/did.json".to_owned();
    assert!(validate_discovery(&document, false).is_err());
}

#[test]
fn validates_platform_identity_and_list_contract() {
    let mut value = identity();
    assert!(validate_platform_identity(&value, false).is_ok());
    value.status = "unknown".to_owned();
    assert!(validate_platform_identity(&value, false).is_err());
    value = identity();
    value.did_document_url = "https://other.example/did.json".to_owned();
    assert!(validate_platform_identity(&value, false).is_err());
    value.did_document_url = "not a URL".to_owned();
    assert!(validate_platform_identity(&value, false).is_err());

    let valid = PlatformIdentityList {
        count: "1".to_owned(),
        data: vec![identity()],
        total: "1".to_owned(),
    };
    assert!(validate_identity_list(&valid, false).is_ok());
    let invalid = PlatformIdentityList {
        count: "2".to_owned(),
        data: vec![identity()],
        total: "1".to_owned(),
    };
    assert!(validate_identity_list(&invalid, false).is_err());
}

#[test]
fn validates_completed_and_pending_sign_contracts() {
    let identity = AgentIdentity {
        agent_did: "did:web:platform.example:agents:one".to_owned(),
        identity_method: IdentityMethod::DidWeb,
        service_did: "did:web:service.example".to_owned(),
        signing_algorithms: vec![SigningAlgorithm::Es256],
        metadata: BTreeMap::new(),
    };
    let claims = ClientAssertionClaims {
        aud: identity.service_did.clone(),
        exp: 1_788_177_900,
        iat: 1_788_177_600,
        iss: identity.agent_did.clone(),
        jti: "assertion-one".to_owned(),
        op: aep_core::AssertionOperation::Enroll,
        resource: None,
        sub: identity.agent_did.clone(),
        additional: BTreeMap::new(),
    };
    let mut completed: PlatformSignResponse = serde_json::from_value(serde_json::json!({
        "agent_did": identity.agent_did,
        "client_assertion": "assertion",
        "expires_at": "2026-08-31T12:05:00Z",
        "issued_at": "2026-08-31T12:00:00Z",
        "jti": "assertion-one",
        "service_did": identity.service_did,
        "status": "completed"
    }))
    .expect("completed response");
    assert_eq!(
        validate_completed_sign(&completed, &claims, &identity).expect("valid response"),
        "assertion"
    );
    completed.client_assertion = Some(String::new());
    assert!(validate_completed_sign(&completed, &claims, &identity).is_err());

    let mut pending: PlatformSignResponse = serde_json::from_value(serde_json::json!({
        "retry_after_seconds": "5",
        "status": "pending"
    }))
    .expect("pending response");
    assert_eq!(
        validate_pending_sign(&pending).expect("valid pending"),
        Duration::from_secs(5)
    );
    pending.retry_after_seconds = Some("301".to_owned());
    assert!(validate_pending_sign(&pending).is_err());
    pending.retry_after_seconds = Some("5".to_owned());
    pending.client_assertion = Some("unexpected".to_owned());
    assert!(validate_pending_sign(&pending).is_err());
}

#[test]
fn applies_platform_cache_and_http_helpers() {
    let cached_at = OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("time");
    let mut entry = DiscoveryCacheEntry {
        cache_control: None,
        cached_at,
        document: discovery(),
        etag: None,
        final_url: Url::parse("https://platform.example/.well-known/aep-platform").expect("URL"),
        last_modified: None,
    };
    assert!(discovery_fresh(
        &entry,
        cached_at + time::Duration::seconds(299)
    ));
    entry.cache_control = Some("max-age=1".to_owned());
    assert!(!discovery_fresh(
        &entry,
        cached_at + time::Duration::seconds(2)
    ));
    entry.cache_control = Some("max-age=invalid".to_owned());
    assert!(!discovery_fresh(&entry, cached_at));
    entry.cache_control = Some("no-store".to_owned());
    assert!(!discovery_fresh(&entry, cached_at));

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=60"),
    );
    headers.insert(header::ETAG, HeaderValue::from_static("\"two\""));
    headers.insert(
        header::LAST_MODIFIED,
        HeaderValue::from_static("Sun, 31 Aug 2026 12:00:00 GMT"),
    );
    merge_cache_headers(&mut entry, &headers);
    assert_eq!(entry.cache_control.as_deref(), Some("max-age=60"));
    assert_eq!(entry.etag.as_deref(), Some("\"two\""));
    assert!(entry.last_modified.is_some());

    assert!(valid_endpoint_path("/v1/aep/identities"));
    assert!(!valid_endpoint_path("https://other.example/path"));
    assert_eq!(encode_path("identity/one"), "identity%2Fone");
    assert!(validate_did("did:web:service.example", "DID").is_ok());
    assert!(validate_did("", "DID").is_err());
    assert!(validate_media_type(&headers, MEDIA_TYPE, "command").is_err());
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    assert!(validate_media_type(&headers, MEDIA_TYPE, "command").is_ok());
}
