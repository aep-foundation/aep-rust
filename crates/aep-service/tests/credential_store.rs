//! The stored-credential grant types and the invariants their store keeps.

use std::{collections::BTreeMap, sync::Arc};

use aep_core::{
    AgentStatus, ApiKeyGrantResponse, BasicGrantResponse, BuiltInGrantResponse, ClaimValues,
    GrantRequest, GrantType, GrantTypeConfig, OAuthBearerGrantResponse, RevokeRequest,
};
use aep_service::*;
use futures::{FutureExt as _, executor::block_on};
use http::{HeaderMap, HeaderValue};
use serde_json::json;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const AGENT_DID: &str = "did:web:agent.example";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_788_177_600).expect("time")
}

fn expiration(created_at: OffsetDateTime) -> String {
    (created_at + Duration::hours(1))
        .format(&Rfc3339)
        .expect("expiration")
}

fn context(grant_type: GrantType) -> GrantContext {
    GrantContext {
        agent_did: AGENT_DID.to_owned(),
        enrollment: EnrollmentRecord {
            agent_did: AGENT_DID.to_owned(),
            claims: ClaimValues::default(),
            created_at: now(),
            owner_action_required: false,
            requirements_pending: Vec::new(),
            since: now(),
            status: AgentStatus::Active,
            updated_at: now(),
            verification_pending: Vec::new(),
        },
        grant_type,
        now: now(),
    }
}

fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.append(
            http::HeaderName::try_from(*name).expect("header name"),
            HeaderValue::try_from(*value).expect("header value"),
        );
    }
    headers
}

fn input(values: &[(&str, &str)]) -> CredentialAuthenticationInput {
    CredentialAuthenticationInput {
        headers: headers(values),
        now: now(),
    }
}

fn api_key(secret: &str, credential_id: &str, header: &str) -> ApiKeyGrantResponse {
    ApiKeyGrantResponse {
        additional: BTreeMap::new(),
        api_key: secret.to_owned(),
        credential_id: credential_id.to_owned(),
        expires_at: expiration(now()),
        header: header.to_owned(),
        scopes: Vec::new(),
    }
}

fn record(credential: BuiltInGrantResponse) -> ServiceCredentialRecord {
    let (credential_id, expires_at) = match &credential {
        BuiltInGrantResponse::OAuthBearer(value) => {
            (value.credential_id.clone(), value.expires_at.clone())
        }
        BuiltInGrantResponse::ApiKey(value) => {
            (value.credential_id.clone(), value.expires_at.clone())
        }
        BuiltInGrantResponse::Basic(value) => {
            (value.credential_id.clone(), value.expires_at.clone())
        }
    };
    ServiceCredentialRecord {
        agent_did: AGENT_DID.to_owned(),
        created_at: now(),
        credential_id,
        expires_at: OffsetDateTime::parse(&expires_at, &Rfc3339).expect("expiration"),
        grant_type: credential.grant_type(),
        credential,
    }
}

fn api_key_definition(
    config: GrantTypeConfig,
    store: Arc<dyn ServiceCredentialStore>,
    issued: ApiKeyGrantResponse,
) -> Result<GrantTypeDefinition, ServiceError> {
    stored_api_key_grant_type(StoredApiKeyGrantTypeOptions {
        config,
        issue: Arc::new(move |_, _| {
            let issued = issued.clone();
            async move { Ok(issued) }.boxed()
        }),
        store,
    })
}

// --- configuration ------------------------------------------------------------------------------

/// APK-CFG-004: `header_names` is issuance guidance, so it has to be a usable list of HTTP field
/// names when it is advertised at all.
#[test]
fn advertised_api_key_headers_must_be_usable() {
    let store = Arc::new(MemoryServiceCredentialStore::default());
    for additional in [
        json!("x-api-key"),
        json!([1]),
        json!(["x api key"]),
        json!(["x-api-key", "X-API-Key"]),
    ] {
        let config = GrantTypeConfig {
            additional: BTreeMap::from([("header_names".to_owned(), additional.clone())]),
            supports_per_credential_revoke: None,
        };
        assert!(
            api_key_definition(config, store.clone(), api_key("secret", "c1", "x-api-key"))
                .is_err(),
            "{additional}"
        );
    }

    // A Service may advertise no header names at all.
    assert!(
        api_key_definition(
            GrantTypeConfig::default(),
            store,
            api_key("secret", "c1", "x-api-key")
        )
        .is_ok()
    );
}

/// APK-RSP-006: when the Service advertises header names, the issued credential uses one of them.
#[test]
fn issued_api_keys_use_an_advertised_header() {
    block_on(async {
        let store = Arc::new(MemoryServiceCredentialStore::default());
        let config = || GrantTypeConfig {
            additional: BTreeMap::from([("header_names".to_owned(), json!(["x-api-key"]))]),
            supports_per_credential_revoke: None,
        };
        let request = GrantRequest {
            additional: BTreeMap::new(),
            grant_type: GrantType::ApiKey,
            requested_scopes: Vec::new(),
        };

        // The comparison ignores case, which is how HTTP field names compare.
        let advertised = api_key_definition(
            config(),
            store.clone(),
            api_key("secret-1", "c1", "X-API-Key"),
        )
        .expect("definition");
        assert!(
            advertised
                .handler
                .expect("handler")
                .grant(&request, &context(GrantType::ApiKey))
                .await
                .is_ok()
        );

        let unadvertised =
            api_key_definition(config(), store, api_key("secret-2", "c2", "x-other-key"))
                .expect("definition");
        assert!(
            unadvertised
                .handler
                .expect("handler")
                .grant(&request, &context(GrantType::ApiKey))
                .await
                .is_err()
        );
    });
}

/// A stored credential grant type is one of the three the specification registers.
#[test]
fn stored_credentials_need_a_built_in_grant_type() {
    block_on(async {
        // The store hands back a match for a grant type that has no registered presentation.
        struct ForeignMatch;

        #[async_trait::async_trait]
        impl ServiceCredentialStore for ForeignMatch {
            async fn authenticate(
                &self,
                _grant_type: &GrantType,
                input: &CredentialAuthenticationInput,
            ) -> Result<Option<CredentialMatch>, ServiceError> {
                Ok(Some(CredentialMatch {
                    agent_did: AGENT_DID.to_owned(),
                    credential_id: "c1".to_owned(),
                    expires_at: input.now + Duration::hours(1),
                    grant_type: GrantType::from("vendor-token"),
                    scopes: Vec::new(),
                }))
            }
            async fn has_presentation(
                &self,
                _grant_type: &GrantType,
                _input: &CredentialAuthenticationInput,
            ) -> Result<bool, ServiceError> {
                Ok(true)
            }
            async fn revoke_credential(
                &self,
                _agent_did: &str,
                _grant_type: &GrantType,
                _credential_id: &str,
                _revoked_at: OffsetDateTime,
            ) -> Result<(), ServiceError> {
                Ok(())
            }
            async fn revoke_grant_type(
                &self,
                _agent_did: &str,
                _grant_type: &GrantType,
                _revoked_at: OffsetDateTime,
            ) -> Result<(), ServiceError> {
                Ok(())
            }
            async fn save(&self, _record: ServiceCredentialRecord) -> Result<(), ServiceError> {
                Ok(())
            }
        }

        let definition = api_key_definition(
            GrantTypeConfig::default(),
            Arc::new(ForeignMatch),
            api_key("secret", "c1", "x-api-key"),
        )
        .expect("definition");
        // The match names another grant type, so the Service will not present it as this one.
        assert!(
            definition
                .handler
                .expect("handler")
                .authenticate(&input(&[("x-api-key", "secret")]))
                .await
                .is_err()
        );
    });
}

// --- issuance -----------------------------------------------------------------------------------

/// An issued credential has to be one the Service can store and later recognize.
#[test]
fn unusable_issued_credentials_are_refused() {
    block_on(async {
        let issue = |issued: ApiKeyGrantResponse| async move {
            let request = GrantRequest {
                additional: BTreeMap::new(),
                grant_type: GrantType::ApiKey,
                requested_scopes: Vec::new(),
            };
            let store = Arc::new(MemoryServiceCredentialStore::default());
            let definition =
                api_key_definition(GrantTypeConfig::default(), store, issued).expect("definition");
            definition
                .handler
                .expect("handler")
                .grant(&request, &context(GrantType::ApiKey))
                .await
        };
        // An expiration that is not RFC 3339, and one that has already passed.
        let mut unparseable = api_key("secret", "c1", "x-api-key");
        unparseable.expires_at = "not-a-timestamp".to_owned();
        assert!(issue(unparseable).await.is_err());

        let mut expired = api_key("secret", "c1", "x-api-key");
        expired.expires_at = now().format(&Rfc3339).expect("time");
        assert!(issue(expired).await.is_err());

        // A credential document the core contract refuses.
        let mut empty_key = api_key("", "c1", "x-api-key");
        empty_key.api_key = String::new();
        assert!(issue(empty_key).await.is_err());
    });
}

// --- the memory store -----------------------------------------------------------------------------

/// The store refuses records that would let two credentials answer to the same presentation.
#[test]
fn the_store_keeps_credentials_distinguishable() {
    block_on(async {
        assert!(
            MemoryServiceCredentialStore::new([record(BuiltInGrantResponse::ApiKey(api_key(
                "secret",
                "c1",
                "x-api-key"
            )))])
            .is_ok()
        );

        // The same identifier twice.
        assert!(
            MemoryServiceCredentialStore::new([
                record(BuiltInGrantResponse::ApiKey(api_key(
                    "secret-1",
                    "c1",
                    "x-api-key"
                ))),
                record(BuiltInGrantResponse::ApiKey(api_key(
                    "secret-2",
                    "c1",
                    "x-api-key"
                ))),
            ])
            .is_err()
        );

        // The same secret in the same field twice.
        assert!(
            MemoryServiceCredentialStore::new([
                record(BuiltInGrantResponse::ApiKey(api_key(
                    "secret",
                    "c1",
                    "x-api-key"
                ))),
                record(BuiltInGrantResponse::ApiKey(api_key(
                    "secret",
                    "c2",
                    "x-api-key"
                ))),
            ])
            .is_err()
        );

        // The same secret in different fields is distinguishable.
        assert!(
            MemoryServiceCredentialStore::new([
                record(BuiltInGrantResponse::ApiKey(api_key(
                    "secret",
                    "c1",
                    "x-api-key"
                ))),
                record(BuiltInGrantResponse::ApiKey(api_key(
                    "secret",
                    "c2",
                    "x-other-key"
                ))),
            ])
            .is_ok()
        );
    });
}

/// A record whose metadata disagrees with the credential document it carries is not storable.
#[test]
fn stored_records_must_agree_with_their_credential() {
    block_on(async {
        let store = MemoryServiceCredentialStore::default();
        let base = || {
            record(BuiltInGrantResponse::ApiKey(api_key(
                "secret",
                "c1",
                "x-api-key",
            )))
        };
        assert!(store.save(base()).await.is_ok());

        let mut no_agent = base();
        no_agent.agent_did = String::new();
        assert!(store.save(no_agent).await.is_err());

        let mut wrong_identifier = base();
        wrong_identifier.credential_id = "c2".to_owned();
        assert!(store.save(wrong_identifier).await.is_err());

        let mut wrong_expiry = base();
        wrong_expiry.expires_at = now() + Duration::hours(2);
        assert!(store.save(wrong_expiry).await.is_err());

        let mut already_expired = base();
        already_expired.created_at = already_expired.expires_at;
        assert!(store.save(already_expired).await.is_err());

        let mut wrong_grant_type = base();
        wrong_grant_type.grant_type = GrantType::Basic;
        assert!(store.save(wrong_grant_type).await.is_err());

        let mut unusable_document = base();
        unusable_document.credential =
            BuiltInGrantResponse::ApiKey(api_key("secret", "c1", "x api key"));
        assert!(store.save(unusable_document).await.is_err());
    });
}

/// APK-PRS-002 and APK-SEC-006: an API key is only a presentation in the field it was issued for,
/// and two of them in one request are not a presentation the Service will act on.
#[test]
fn api_keys_answer_only_in_their_own_field() {
    block_on(async {
        let store = MemoryServiceCredentialStore::new([
            record(BuiltInGrantResponse::ApiKey(api_key(
                "secret-1",
                "c1",
                "x-api-key",
            ))),
            record(BuiltInGrantResponse::ApiKey(api_key(
                "secret-2",
                "c2",
                "x-other-key",
            ))),
        ])
        .expect("store");

        let matched = store
            .authenticate(&GrantType::ApiKey, &input(&[("x-api-key", "secret-1")]))
            .await
            .expect("answered")
            .expect("match");
        assert_eq!(matched.credential_id, "c1");

        // The right secret in the wrong advertised field is not that credential.
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &input(&[("x-other-key", "secret-1")]))
                .await
                .expect("answered")
                .is_none()
        );

        // Two presentations at once are ambiguous, but the Service can still tell one was made.
        let ambiguous = input(&[("x-api-key", "secret-1"), ("x-other-key", "secret-2")]);
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &ambiguous)
                .await
                .expect("answered")
                .is_none()
        );
        assert!(
            store
                .has_presentation(&GrantType::ApiKey, &ambiguous)
                .await
                .expect("answered")
        );

        // A field no issued credential uses is not a presentation at all.
        assert!(
            !store
                .has_presentation(&GrantType::ApiKey, &input(&[("x-third-key", "secret-1")]))
                .await
                .expect("answered")
        );

        // A grant type with no registered presentation never matches.
        assert!(
            !store
                .has_presentation(
                    &GrantType::from("vendor-token"),
                    &input(&[("x-api-key", "secret-1")])
                )
                .await
                .expect("answered")
        );
    });
}

/// OAB-PRS and BSC-PRS: a session credential is presented through either accepted carrier.
#[test]
fn session_credentials_answer_through_either_carrier() {
    block_on(async {
        let store = MemoryServiceCredentialStore::new([record(BuiltInGrantResponse::OAuthBearer(
            OAuthBearerGrantResponse {
                access_token: "opaque-token".to_owned(),
                additional: BTreeMap::new(),
                credential_id: "c1".to_owned(),
                expires_at: expiration(now()),
                scopes: vec!["read".to_owned()],
                token_type: "Bearer".to_owned(),
            },
        ))])
        .expect("store");

        for carrier in ["authorization", "aep-authorization"] {
            let matched = store
                .authenticate(
                    &GrantType::OAuthBearer,
                    &input(&[(carrier, "Bearer opaque-token")]),
                )
                .await
                .expect("answered")
                .expect("match");
            assert_eq!(matched.credential_id, "c1");
            assert_eq!(matched.scopes, vec!["read".to_owned()]);
        }

        // A scheme that is not this grant type's is not its presentation.
        assert!(
            !store
                .has_presentation(
                    &GrantType::OAuthBearer,
                    &input(&[("authorization", "Basic YWdlbnQ6c2VjcmV0")])
                )
                .await
                .expect("answered")
        );

        // A Basic credential answers in the same two places.
        let basic = MemoryServiceCredentialStore::new([record(BuiltInGrantResponse::Basic(
            BasicGrantResponse {
                additional: BTreeMap::new(),
                credential_id: "c2".to_owned(),
                expires_at: expiration(now()),
                password: "secret".to_owned(),
                realm: None,
                scopes: Vec::new(),
                username: "agent".to_owned(),
            },
        ))])
        .expect("store");
        let matched = basic
            .authenticate(
                &GrantType::Basic,
                &input(&[("aep-authorization", "Basic YWdlbnQ6c2VjcmV0")]),
            )
            .await
            .expect("answered")
            .expect("match");
        assert_eq!(matched.credential_id, "c2");
    });
}

/// A revoked or expired credential stops answering, and revocation only reaches its own owner.
#[test]
fn revoked_and_expired_credentials_stop_answering() {
    block_on(async {
        let store = MemoryServiceCredentialStore::new([
            record(BuiltInGrantResponse::ApiKey(api_key(
                "secret-1",
                "c1",
                "x-api-key",
            ))),
            record(BuiltInGrantResponse::ApiKey(api_key(
                "secret-2",
                "c2",
                "x-other-key",
            ))),
        ])
        .expect("store");
        let presented = |secret: &'static str, header: &'static str| input(&[(header, secret)]);

        // Revoking for another Agent, or under another grant type, leaves the record alone.
        store
            .revoke_credential("did:web:other.example", &GrantType::ApiKey, "c1", now())
            .await
            .expect("revoked");
        store
            .revoke_credential(AGENT_DID, &GrantType::Basic, "c1", now())
            .await
            .expect("revoked");
        store
            .revoke_credential(AGENT_DID, &GrantType::ApiKey, "missing", now())
            .await
            .expect("revoked");
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &presented("secret-1", "x-api-key"))
                .await
                .expect("answered")
                .is_some()
        );

        store
            .revoke_credential(AGENT_DID, &GrantType::ApiKey, "c1", now())
            .await
            .expect("revoked");
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &presented("secret-1", "x-api-key"))
                .await
                .expect("answered")
                .is_none()
        );
        // The other credential is untouched.
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &presented("secret-2", "x-other-key"))
                .await
                .expect("answered")
                .is_some()
        );

        // Revoking the grant type reaches every credential the Agent holds under it.
        store
            .revoke_grant_type(AGENT_DID, &GrantType::ApiKey, now())
            .await
            .expect("revoked");
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &presented("secret-2", "x-other-key"))
                .await
                .expect("answered")
                .is_none()
        );

        // A credential past its expiration does not answer either.
        let expiring = MemoryServiceCredentialStore::new([record(BuiltInGrantResponse::ApiKey(
            api_key("secret-3", "c3", "x-api-key"),
        ))])
        .expect("store");
        let later = CredentialAuthenticationInput {
            headers: headers(&[("x-api-key", "secret-3")]),
            now: now() + Duration::hours(2),
        };
        assert!(
            expiring
                .authenticate(&GrantType::ApiKey, &later)
                .await
                .expect("answered")
                .is_none()
        );
    });
}

/// The handler revokes exactly what the request names.
#[test]
fn revoke_requests_reach_the_named_credential() {
    block_on(async {
        let store = Arc::new(
            MemoryServiceCredentialStore::new([
                record(BuiltInGrantResponse::ApiKey(api_key(
                    "secret-1",
                    "c1",
                    "x-api-key",
                ))),
                record(BuiltInGrantResponse::ApiKey(api_key(
                    "secret-2",
                    "c2",
                    "x-other-key",
                ))),
            ])
            .expect("store"),
        );
        let definition = api_key_definition(
            GrantTypeConfig::default(),
            store.clone(),
            api_key("secret-3", "c3", "x-api-key"),
        )
        .expect("definition");
        let handler = definition.handler.expect("handler");

        handler
            .revoke(
                &RevokeRequest {
                    additional: BTreeMap::new(),
                    all_grant_types: None,
                    credential_id: Some("c1".to_owned()),
                    grant_type: Some(GrantType::ApiKey),
                },
                &context(GrantType::ApiKey),
            )
            .await
            .expect("revoked");
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &input(&[("x-api-key", "secret-1")]))
                .await
                .expect("answered")
                .is_none()
        );
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &input(&[("x-other-key", "secret-2")]))
                .await
                .expect("answered")
                .is_some()
        );

        handler
            .revoke(
                &RevokeRequest {
                    additional: BTreeMap::new(),
                    all_grant_types: Some(aep_core::StringBoolean::True),
                    credential_id: None,
                    grant_type: None,
                },
                &context(GrantType::ApiKey),
            )
            .await
            .expect("revoked");
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &input(&[("x-other-key", "secret-2")]))
                .await
                .expect("answered")
                .is_none()
        );
    });
}

/// A store that hands back a match it cannot stand behind is a store failure, not an
/// authenticated principal.
#[test]
fn unusable_matches_are_refused() {
    block_on(async {
        struct FixedMatch(CredentialMatch);

        #[async_trait::async_trait]
        impl ServiceCredentialStore for FixedMatch {
            async fn authenticate(
                &self,
                _grant_type: &GrantType,
                _input: &CredentialAuthenticationInput,
            ) -> Result<Option<CredentialMatch>, ServiceError> {
                Ok(Some(self.0.clone()))
            }
            async fn has_presentation(
                &self,
                _grant_type: &GrantType,
                _input: &CredentialAuthenticationInput,
            ) -> Result<bool, ServiceError> {
                Ok(true)
            }
            async fn revoke_credential(
                &self,
                _agent_did: &str,
                _grant_type: &GrantType,
                _credential_id: &str,
                _revoked_at: OffsetDateTime,
            ) -> Result<(), ServiceError> {
                Ok(())
            }
            async fn revoke_grant_type(
                &self,
                _agent_did: &str,
                _grant_type: &GrantType,
                _revoked_at: OffsetDateTime,
            ) -> Result<(), ServiceError> {
                Ok(())
            }
            async fn save(&self, _record: ServiceCredentialRecord) -> Result<(), ServiceError> {
                Ok(())
            }
        }

        let usable = CredentialMatch {
            agent_did: AGENT_DID.to_owned(),
            credential_id: "c1".to_owned(),
            expires_at: now() + Duration::hours(1),
            grant_type: GrantType::ApiKey,
            scopes: Vec::new(),
        };
        for unusable in [
            CredentialMatch {
                agent_did: String::new(),
                ..usable.clone()
            },
            CredentialMatch {
                credential_id: String::new(),
                ..usable.clone()
            },
            CredentialMatch {
                expires_at: now(),
                ..usable.clone()
            },
        ] {
            let definition = api_key_definition(
                GrantTypeConfig::default(),
                Arc::new(FixedMatch(unusable)),
                api_key("secret", "c1", "x-api-key"),
            )
            .expect("definition");
            assert!(
                definition
                    .handler
                    .expect("handler")
                    .authenticate(&input(&[("x-api-key", "secret")]))
                    .await
                    .is_err()
            );
        }

        // A usable match becomes a session-credential principal.
        let definition = api_key_definition(
            GrantTypeConfig::default(),
            Arc::new(FixedMatch(usable)),
            api_key("secret", "c1", "x-api-key"),
        )
        .expect("definition");
        let principal = definition
            .handler
            .expect("handler")
            .authenticate(&input(&[("x-api-key", "secret")]))
            .await
            .expect("answered")
            .expect("principal");
        assert_eq!(
            principal.authentication_kind,
            AuthenticationKind::SessionCredential
        );
        assert_eq!(
            principal.authentication_method,
            aep_core::AuthenticationMethod::ApiKey
        );
    });
}

/// The handler reports a presentation through its own store, and refuses to record a credential
/// that names no Agent.
#[test]
fn handlers_report_presentations_and_require_an_agent() {
    block_on(async {
        let store = Arc::new(
            MemoryServiceCredentialStore::new([record(BuiltInGrantResponse::ApiKey(api_key(
                "secret",
                "c1",
                "x-api-key",
            )))])
            .expect("store"),
        );
        let definition = api_key_definition(
            GrantTypeConfig::default(),
            store,
            api_key("secret-2", "c2", "x-api-key"),
        )
        .expect("definition");
        let handler = definition.handler.expect("handler");
        assert!(
            handler
                .has_presentation(&input(&[("x-api-key", "secret")]))
                .await
                .expect("answered")
        );
        assert!(
            !handler
                .has_presentation(&input(&[("x-other-key", "secret")]))
                .await
                .expect("answered")
        );

        // A Grant context with no Agent DID has nothing to issue the credential to.
        let mut anonymous = context(GrantType::ApiKey);
        anonymous.agent_did = String::new();
        assert!(
            handler
                .grant(
                    &GrantRequest {
                        additional: BTreeMap::new(),
                        grant_type: GrantType::ApiKey,
                        requested_scopes: Vec::new(),
                    },
                    &anonymous,
                )
                .await
                .is_err()
        );
    });
}
