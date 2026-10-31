use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use aep_core::*;
use aep_service::*;
use async_trait::async_trait;
use http::{HeaderMap, HeaderValue};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{AdapterRequest, expected, input, role};

type Result<T> = std::result::Result<T, String>;

pub async fn evaluate(request: &AdapterRequest) -> Result<bool> {
    match request.vector.id.as_str() {
        "wire-shapes" => wire_shapes(request),
        "structural-limits" => structural_limits(request),
        "enrollment-lifecycle" => lifecycle(request).await,
        "grant-guidance" => grant_guidance(request).await,
        id => Err(format!("Unsupported Service Documents vector {id}")),
    }
}

fn catalog(value: &Value) -> Value {
    let mut document = json!({"aep_version":"1.0","bindings":{"supported":["http"]},
        "commands":{"supported":["inspect"]},"core":{"signing_algorithms":["EdDSA","ES256"]},
        "http":{},"identity":{"methods":[]},"service":{"did":"did:example:service"}});
    document
        .as_object_mut()
        .unwrap()
        .extend(value.as_object().unwrap().clone());
    document
}

fn wire_valid(schema: &str, value: &Value) -> Result<bool> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    Ok(match schema {
        "service-documents.schema.json" => {
            parse_inspect_document(&serde_json::to_vec(&catalog(value)).unwrap()).is_ok()
        }
        "inspect-document.schema.json" => parse_inspect_document(&bytes).is_ok(),
        "enroll-request.schema.json" => parse_enroll_request(&bytes).is_ok(),
        "enroll-response.schema.json" => parse_enroll_response(&bytes).is_ok(),
        "problem.schema.json" => parse_problem_details(&bytes).is_ok(),
        "portable-service-document.schema.json" => {
            parse_portable_service_document(&bytes, value["id"].as_str().unwrap_or_default())
                .is_ok()
        }
        _ => return Err(format!("Unsupported schema {schema}")),
    })
}

fn wire_shapes(request: &AdapterRequest) -> Result<bool> {
    let cases: Vec<Value> = input(request, "cases")?;
    let wanted: Vec<Value> = expected(request, "cases")?;
    if cases.len() != wanted.len() {
        return Ok(false);
    }
    for (case, wanted) in cases.iter().zip(&wanted) {
        let valid = wire_valid(case["schema"].as_str().ok_or("schema")?, &case["value"])?;
        if case["name"] != wanted["name"] || json!(valid) != wanted["valid"] {
            return Ok(false);
        }
    }
    Ok(true)
}

fn structural_limits(request: &AdapterRequest) -> Result<bool> {
    let cases: Vec<Value> = input(request, "cases")?;
    let wanted: Vec<Value> = expected(request, "cases")?;
    let descriptor: Value = input(request, "descriptor")?;
    let portable: Value = input(request, "document")?;
    if cases.len() != wanted.len() {
        return Ok(false);
    }
    for (case, wanted) in cases.iter().zip(&wanted) {
        let number = |name: &str| -> Result<usize> {
            usize::try_from(case[name].as_u64().ok_or(name)?).map_err(|e| e.to_string())
        };
        let mut doc = portable.clone();
        let mut descriptors = vec![descriptor.clone()];
        let mut is_catalog = true;
        match case["kind"].as_str().ok_or("kind")? {
            "catalog" => {
                descriptors = (0..number("count")?)
                    .map(|i| {
                        let mut d = descriptor.clone();
                        d["id"] = json!(format!("doc-{i}"));
                        d
                    })
                    .collect()
            }
            "duplicate-ids" => descriptors.push(descriptor.clone()),
            "duplicate-media" => {
                let rep = descriptors[0]["representations"][0].clone();
                descriptors[0]["representations"]
                    .as_array_mut()
                    .unwrap()
                    .push(rep);
            }
            "title" => descriptors[0]["title"] = json!("a".repeat(number("length")?)),
            "url" => {
                let prefix = "https://example.com/";
                descriptors[0]["representations"][0]["url"] = json!(format!(
                    "{prefix}{}",
                    "a".repeat(number("length")?.saturating_sub(prefix.len()))
                ));
            }
            kind => {
                is_catalog = false;
                match kind {
                    "blocks" => {
                        doc["content"] =
                            json!(vec![doc["content"][0].clone(); number("content_count")?]);
                        doc["summary"] = json!(vec![
                            portable["content"][0].clone();
                            number("summary_count")?
                        ]);
                    }
                    "sections" => {
                        let mut block = doc["content"][0].clone();
                        for _ in 0..number("depth")? {
                            block = json!({"type":"section","title":"Section","blocks":[block]});
                        }
                        doc["content"] = json!([block]);
                    }
                    "text" => doc["content"][0]["text"] = json!("x".repeat(number("length")?)),
                    "list" => {
                        doc["content"] =
                            json!([{"type":"bulleted_list","items":vec!["x";number("count")?]}])
                    }
                    _ => return Err(format!("Unsupported structure {kind}")),
                }
            }
        }
        let valid = if is_catalog {
            wire_valid(
                "service-documents.schema.json",
                &json!({"extensions":{"supported":[SERVICE_DOCUMENTS_EXTENSION]},"service_documents":descriptors}),
            )?
        } else {
            wire_valid("portable-service-document.schema.json", &doc)?
        };
        if wanted["name"] != case["name"] || wanted["valid"] != json!(valid) {
            return Ok(false);
        }
    }
    Ok(true)
}

struct CountingPolicy(Arc<AtomicUsize>);
#[async_trait]
impl EnrollmentPolicy for CountingPolicy {
    async fn decide(
        &self,
        _request: &EnrollRequest,
        _now: OffsetDateTime,
    ) -> std::result::Result<EnrollmentDecision, ServiceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(EnrollmentDecision::default())
    }
}

struct Fixture {
    service: Arc<Service>,
    store: Arc<MemoryEnrollmentStore>,
    credentials: Arc<MemoryServiceCredentialStore>,
    effects: Arc<AtomicUsize>,
    issued: Arc<AtomicUsize>,
}

fn fixture(ids: &[String], records: Vec<EnrollmentRecord>) -> Result<Fixture> {
    let mut options = role::document_service_options()?;
    let store = Arc::new(MemoryEnrollmentStore::new(records).map_err(|e| e.to_string())?);
    let credentials = Arc::new(MemoryServiceCredentialStore::default());
    let effects = Arc::new(AtomicUsize::new(0));
    let issued = Arc::new(AtomicUsize::new(0));
    options.enrollment_store = Some(store.clone());
    options.enrollment_policy = Some(Arc::new(CountingPolicy(effects.clone())));
    options.claims.required = vec![ClaimName::ContactEmail];
    options.extensions = vec![SERVICE_DOCUMENTS_EXTENSION.into()];
    options.service_documents = Some(
        ids.iter()
            .map(|id| ServiceDocument {
                id: id.clone(),
                document_type: "terms_of_service".into(),
                title: id.clone(),
                enrollment: DocumentEnrollment::Required,
                representations: vec![DocumentRepresentation {
                    media_type: "text/html".into(),
                    url: format!("https://service.example/{id}"),
                }],
            })
            .collect(),
    );
    let counter = issued.clone();
    options.grant_types = vec![
        stored_api_key_grant_type(StoredApiKeyGrantTypeOptions {
            config: Default::default(),
            store: credentials.clone(),
            issue: Arc::new(move |_, _| {
                counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Ok(serde_json::from_value(role::grant_payload(
                        &GrantType::ApiKey,
                    ))?)
                })
            }),
        })
        .map_err(|e| e.to_string())?,
    ];
    options.authentication_methods =
        vec![AuthenticationMethod::AepJwt, AuthenticationMethod::ApiKey];
    Ok(Fixture {
        service: Service::new(options).map_err(|e| e.to_string())?,
        store,
        credentials,
        effects,
        issued,
    })
}

fn record(existing: &Value) -> Result<EnrollmentRecord> {
    let time =
        OffsetDateTime::parse("2026-08-01T10:00:00Z", &Rfc3339).map_err(|e| e.to_string())?;
    Ok(EnrollmentRecord {
        agent_did: "did:web:agent.example".into(),
        claims: serde_json::from_value(existing["claims"].clone()).map_err(|e| e.to_string())?,
        acknowledged_document_ids: serde_json::from_value(
            existing["acknowledged_document_ids"].clone(),
        )
        .map_err(|e| e.to_string())?,
        required_document_ids: vec![],
        created_at: time,
        updated_at: time,
        since: time,
        status: serde_json::from_value(existing["status"].clone()).map_err(|e| e.to_string())?,
        owner_action_required: false,
        requirements_pending: vec![],
        verification_pending: vec![],
    })
}

async fn command(
    f: &Fixture,
    operation: AssertionOperation,
    mut body: Value,
    key: &str,
    jti: &str,
) -> Result<ServiceResponse> {
    let options = IdempotentCommandOptions {
        client_assertion: role::signed_assertion(operation, None, jti)?,
        idempotency_key: key.into(),
    };
    if operation == AssertionOperation::Enroll {
        body["agent_did"] = json!("did:web:agent.example");
    }
    let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    match operation {
        AssertionOperation::Enroll => f.service.enroll(&bytes, options).await,
        AssertionOperation::Grant => f.service.grant(&bytes, options).await,
        _ => return Err("unsupported document command".into()),
    }
    .map_err(|e| e.to_string())
}

async fn credential_ids(f: &Fixture) -> Result<Vec<String>> {
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("opaque-api-key"));
    let credential = f
        .credentials
        .authenticate(
            &GrantType::ApiKey,
            &CredentialAuthenticationInput {
                headers,
                now: OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).unwrap(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(credential.into_iter().map(|c| c.credential_id).collect())
}

async fn lifecycle(request: &AdapterRequest) -> Result<bool> {
    let original = record(&input::<Value>(request, "existing")?)?;
    let ids: Vec<String> = input(request, "current_required_ids")?;
    let initial = fixture(&original.acknowledged_document_ids, vec![original.clone()])?;
    let issued = command(
        &initial,
        AssertionOperation::Grant,
        json!({"grant_type":"api-key"}),
        "seed",
        "seed",
    )
    .await?;
    if issued.status != 200 {
        return Ok(false);
    }
    // Reconfigure the required list while retaining the actual enrollment and credential stores.
    let mut options = role::document_service_options()?;
    options.enrollment_store = Some(initial.store.clone());
    options.enrollment_policy = Some(Arc::new(CountingPolicy(initial.effects.clone())));
    options.extensions = vec![SERVICE_DOCUMENTS_EXTENSION.into()];
    options.service_documents = fixture(&ids, vec![])?
        .service
        .inspect_document()
        .service_documents;
    options.claims.required = vec![ClaimName::ContactEmail];
    options.grant_types = vec![
        stored_api_key_grant_type(StoredApiKeyGrantTypeOptions {
            config: Default::default(),
            store: initial.credentials.clone(),
            issue: Arc::new(|_, _| {
                Box::pin(async {
                    Ok(serde_json::from_value(role::grant_payload(
                        &GrantType::ApiKey,
                    ))?)
                })
            }),
        })
        .map_err(|e| e.to_string())?,
    ];
    let f = Fixture {
        service: Service::new(options).map_err(|e| e.to_string())?,
        ..initial
    };
    let operations: Vec<Value> = input(request, "operations")?;
    let wanted: Vec<Value> = expected(request, "operations")?;
    if operations.len() != wanted.len() {
        return Ok(false);
    }
    for (i, (operation, wanted)) in operations.iter().zip(&wanted).enumerate() {
        if let Some(required) = operation.get("mark_required") {
            let mut current = f
                .store
                .find(&original.agent_did)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("record")?;
            current.required_document_ids =
                serde_json::from_value(required.clone()).map_err(|e| e.to_string())?;
            f.store.save(current).await.map_err(|e| e.to_string())?;
        }
        let before = f
            .store
            .find(&original.agent_did)
            .await
            .map_err(|e| e.to_string())?;
        let effects = f.effects.load(Ordering::SeqCst);
        let mut enrollment = json!({});
        for key in ["claims", "acknowledged_document_ids"] {
            if let Some(value) = operation.get(key) {
                enrollment[key] = value.clone();
            }
        }
        let result = command(
            &f,
            AssertionOperation::Enroll,
            enrollment,
            operation["key"].as_str().ok_or("key")?,
            &format!("document-{i}"),
        )
        .await?;
        let body = result.body.to_json().map_err(|e| e.to_string())?;
        let saved = f
            .store
            .find(&original.agent_did)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("record")?;
        if wanted["http_status"] != json!(result.status) || wanted["name"] != operation["name"] {
            return Ok(false);
        }
        for field in ["acknowledged_document_ids", "code"] {
            if let Some(value) = wanted.get(field)
                && body.get(field) != Some(value)
            {
                return Ok(false);
            }
        }
        if let Some(ids) = wanted.get("stored_ids")
            && *ids != json!(saved.acknowledged_document_ids)
        {
            return Ok(false);
        }
        if let Some(value) = wanted.get("policy_effects_repeated")
            && *value != json!(f.effects.load(Ordering::SeqCst) != effects)
        {
            return Ok(false);
        }
        if let Some(value) = wanted.get("mutated")
            && *value != json!(before.as_ref() != Some(&saved))
        {
            return Ok(false);
        }
        if let Some(value) = wanted.get("requirement_satisfied")
            && *value != json!(saved.required_document_ids.is_empty())
        {
            return Ok(false);
        }
        if saved.agent_did != original.agent_did
            || saved.created_at != original.created_at
            || saved.since != original.since
        {
            return Ok(false);
        }
        if i == 0 {
            let grant = command(
                &f,
                AssertionOperation::Grant,
                json!({"grant_type":"api-key"}),
                "missing",
                "missing",
            )
            .await?;
            if grant.body.to_json().map_err(|e| e.to_string())?["required_document_ids"]
                != request.case.expected["outstanding_ids_after_update"]
            {
                return Ok(false);
            }
        }
    }
    let saved = f
        .store
        .find(&original.agent_did)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("record")?;
    if serde_json::to_value(&saved.claims).map_err(|e| e.to_string())?
        != request.case.expected["claims"]
        || json!(credential_ids(&f).await?) != request.case.expected["credential_ids"]
    {
        return Ok(false);
    }
    for (i, state) in input::<Vec<AgentStatus>>(request, "lifecycle_states")?
        .into_iter()
        .enumerate()
    {
        let mut staged = saved.clone();
        staged.status = state;
        f.store.save(staged).await.map_err(|e| e.to_string())?;
        command(
            &f,
            AssertionOperation::Enroll,
            json!({"acknowledged_document_ids":[]}),
            &format!("state-{i}"),
            &format!("state-{i}"),
        )
        .await?;
        if f.store
            .find(&original.agent_did)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("record")?
            .status
            != state
        {
            return Ok(false);
        }
    }
    Ok([
        "identity_preserved",
        "creation_preserved",
        "unchanged_state_timestamp_preserved",
        "unrelated_lifecycle_states_preserved",
    ]
    .into_iter()
    .all(|key| request.case.expected[key] == json!(true)))
}

async fn grant_guidance(request: &AdapterRequest) -> Result<bool> {
    let ids: Vec<String> = input(request, "required_document_ids")?;
    let original = record(&json!({"claims":{},"acknowledged_document_ids":[],"status":"active"}))?;
    let f = fixture(&ids, vec![original])?;
    let response = command(
        &f,
        AssertionOperation::Grant,
        json!({"grant_type":"api-key"}),
        "grant",
        "grant",
    )
    .await?;
    let body = response.body.to_json().map_err(|e| e.to_string())?;
    if json!(response.status) != request.case.expected["grant_status"]
        || json!(f.issued.load(Ordering::SeqCst) > 0) != request.case.expected["credential_issued"]
    {
        return Ok(false);
    }
    let problem: Value = input(request, "problem")?;
    for key in [
        "code",
        "status",
        "owner_action_required",
        "requirements_pending",
        "required_document_ids",
    ] {
        if body[key] != problem[key] {
            return Ok(false);
        }
    }
    let unrecognized = fixture(&ids, vec![])?;
    let response = command(
        &unrecognized,
        AssertionOperation::Grant,
        json!({"grant_type":"api-key"}),
        "unknown",
        "unknown",
    )
    .await?;
    let body = response.body.to_json().map_err(|e| e.to_string())?;
    let expected_unknown = &request.case.expected["unrecognized"];
    if json!(response.status) != expected_unknown["http_status"]
        || body["code"] != expected_unknown["code"]
        || json!(
            body.get("required_document_ids").is_some()
                || body.get("requirements_pending").is_some()
        ) != expected_unknown["requirements_disclosed"]
    {
        return Ok(false);
    }
    let enroll: Vec<Value> = input(request, "enroll_requests")?;
    let wanted: Vec<Value> = expected(request, "enroll_requests")?;
    if enroll.len() != wanted.len() {
        return Ok(false);
    }
    for (i, (body, wanted)) in enroll.iter().zip(&wanted).enumerate() {
        let response = command(
            &unrecognized,
            AssertionOperation::Enroll,
            body.clone(),
            &format!("enroll-{i}"),
            &format!("enroll-{i}"),
        )
        .await?;
        let body = response.body.to_json().map_err(|e| e.to_string())?;
        if json!(response.status) != wanted["http_status"] {
            return Ok(false);
        }
        for key in ["code", "acknowledged_document_ids"] {
            if let Some(value) = wanted.get(key)
                && body.get(key) != Some(value)
            {
                return Ok(false);
            }
        }
        if let Some(value) = wanted.get("missing_documents_accepted") {
            let saved = unrecognized
                .store
                .find("did:web:agent.example")
                .await
                .map_err(|e| e.to_string())?
                .ok_or("record")?;
            if *value
                != json!(
                    ids.iter()
                        .any(|id| saved.acknowledged_document_ids.contains(id))
                )
            {
                return Ok(false);
            }
        }
    }
    Ok(f.issued.load(Ordering::SeqCst) == 0 && credential_ids(&f).await?.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterCase, VectorMetadata};

    fn request(id: &str, input: Value, expected: Value) -> AdapterRequest {
        AdapterRequest {
            case: AdapterCase {
                input: input.as_object().unwrap().clone(),
                expected: expected.as_object().unwrap().clone(),
            },
            expectation: "required".into(),
            profile: "service-documents".into(),
            protocol_version: "1".into(),
            role: "service".into(),
            sequence: 1,
            vector: VectorMetadata {
                category: "service-documents".into(),
                drafts: vec![],
                id: id.into(),
                title: id.into(),
            },
        }
    }

    #[tokio::test]
    async fn wire_and_structural_checks_are_falsifiable() {
        let mut wire = request(
            "wire-shapes",
            json!({"cases":[{"name":"empty","schema":"enroll-request.schema.json","value":{"agent_did":"did:example:agent","acknowledged_document_ids":[]}}]}),
            json!({"cases":[{"name":"empty","valid":true}]}),
        );
        assert!(evaluate(&wire).await.unwrap());
        wire.case.input["cases"][0]["value"]["acknowledged_document_ids"] = json!(null);
        assert!(!evaluate(&wire).await.unwrap());
        let mut bounds = request(
            "structural-limits",
            json!({"descriptor":{},"document":{"format":"aep-service-document","version":"1.0","id":"terms","content":[{"type":"paragraph","text":"x"}]},"cases":[{"name":"text","kind":"text","length":16384}]}),
            json!({"cases":[{"name":"text","valid":true}]}),
        );
        assert!(evaluate(&bounds).await.unwrap());
        bounds.case.input["cases"][0]["length"] = json!(16385);
        assert!(!evaluate(&bounds).await.unwrap());
    }

    #[tokio::test]
    async fn lifecycle_checks_observe_stored_acknowledgements_and_credentials() {
        let mut lifecycle = request(
            "enrollment-lifecycle",
            json!({
                "existing":{"status":"active","claims":{"contact.email":"owner@example.com"},"acknowledged_document_ids":["terms"]},
                "current_required_ids":["terms","notice","later"],
                "operations":[{"name":"update","key":"update","acknowledged_document_ids":["notice"]},{"name":"retry","key":"update","acknowledged_document_ids":["notice"]}],
                "lifecycle_states":["suspended","terminated","unavailable"]
            }),
            json!({
                "operations":[{"name":"update","http_status":200,"acknowledged_document_ids":["notice"],"stored_ids":["terms","notice"]},{"name":"retry","http_status":200,"acknowledged_document_ids":["notice"],"policy_effects_repeated":false}],
                "outstanding_ids_after_update":["later"],"claims":{"contact.email":"owner@example.com"},"credential_ids":["credential-1"],
                "identity_preserved":true,"creation_preserved":true,"unchanged_state_timestamp_preserved":true,"unrelated_lifecycle_states_preserved":true
            }),
        );
        assert!(evaluate(&lifecycle).await.unwrap());
        lifecycle.case.expected["operations"][0]["stored_ids"] =
            json!(["terms", "notice", "later"]);
        assert!(!evaluate(&lifecycle).await.unwrap());
    }

    #[tokio::test]
    async fn guidance_checks_observe_nonissuance_and_unrecognized_callers() {
        let mut guidance = request(
            "grant-guidance",
            json!({
                "required_document_ids":["terms"],"problem":{"code":"requirements_unmet","status":422,"owner_action_required":"true","requirements_pending":["contact.email","service_documents"],"required_document_ids":["terms"]},
                "enroll_requests":[{"name":"omitted","claims":{"contact.email":"owner@example.com"}},{"name":"empty","claims":{"contact.email":"owner@example.com"},"acknowledged_document_ids":[]}]
            }),
            json!({"grant_status":422,"credential_issued":false,
                "unrecognized":{"http_status":401,"code":"not_recognized","requirements_disclosed":false},
                "enroll_requests":[{"name":"omitted","http_status":422,"code":"requirements_unmet"},{"name":"empty","http_status":200,"acknowledged_document_ids":[],"missing_documents_accepted":false}]
            }),
        );
        assert!(evaluate(&guidance).await.unwrap());
        guidance.case.expected["credential_issued"] = json!(true);
        assert!(!evaluate(&guidance).await.unwrap());
    }
}
