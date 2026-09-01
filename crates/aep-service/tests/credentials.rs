use std::{collections::BTreeMap, sync::Arc};

use aep_core::{
    AgentStatus, ApiKeyGrantResponse, BasicGrantResponse, BuiltInGrantResponse, ClaimValues,
    GrantRequest, GrantType, GrantTypeConfig, OAuthBearerGrantResponse, RevokeRequest,
    StringBoolean,
};
use aep_service::{
    AuthenticationKind, CredentialAuthenticationInput, EnrollmentRecord, GrantContext,
    MemoryServiceCredentialStore, ServiceCredentialRecord, ServiceCredentialStore,
    StoredApiKeyGrantTypeOptions, StoredBasicGrantTypeOptions, StoredOAuthBearerGrantTypeOptions,
    stored_api_key_grant_type, stored_basic_grant_type, stored_oauth_bearer_grant_type,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::{FutureExt as _, executor::block_on};
use http::{HeaderMap, HeaderValue, header};
use serde_json::json;
use time::{Duration, OffsetDateTime};

#[test]
fn issues_authenticates_and_revokes_built_in_credentials() {
    block_on(async {
        let store = Arc::new(MemoryServiceCredentialStore::default());
        let oauth = stored_oauth_bearer_grant_type(StoredOAuthBearerGrantTypeOptions {
            config: GrantTypeConfig::default(),
            issue: Arc::new(|_, context| {
                async move {
                    Ok(OAuthBearerGrantResponse {
                        access_token: "oauth-secret".to_owned(),
                        additional: BTreeMap::new(),
                        credential_id: "oauth-1".to_owned(),
                        expires_at: expiration(context.now),
                        scopes: vec!["read".to_owned()],
                        token_type: "Bearer".to_owned(),
                    })
                }
                .boxed()
            }),
            store: store.clone(),
        })
        .expect("OAuth Bearer definition");
        let api_key = stored_api_key_grant_type(StoredApiKeyGrantTypeOptions {
            config: GrantTypeConfig {
                additional: BTreeMap::from([("header_names".to_owned(), json!(["x-api-key"]))]),
                supports_per_credential_revoke: None,
            },
            issue: Arc::new(|_, context| {
                async move {
                    Ok(ApiKeyGrantResponse {
                        additional: BTreeMap::new(),
                        api_key: "api-secret".to_owned(),
                        credential_id: "api-1".to_owned(),
                        expires_at: expiration(context.now),
                        header: "X-API-Key".to_owned(),
                        scopes: vec!["purchase".to_owned()],
                    })
                }
                .boxed()
            }),
            store: store.clone(),
        })
        .expect("API-key definition");
        let basic = stored_basic_grant_type(StoredBasicGrantTypeOptions {
            config: GrantTypeConfig::default(),
            issue: Arc::new(|_, context| {
                async move {
                    Ok(BasicGrantResponse {
                        additional: BTreeMap::new(),
                        credential_id: "basic-1".to_owned(),
                        expires_at: expiration(context.now),
                        password: "basic-secret".to_owned(),
                        realm: Some("service".to_owned()),
                        scopes: vec!["read".to_owned()],
                        username: "agent".to_owned(),
                    })
                }
                .boxed()
            }),
            store: store.clone(),
        })
        .expect("Basic definition");

        assert_eq!(
            api_key
                .config
                .as_ref()
                .and_then(|config| config.supports_per_credential_revoke),
            Some(StringBoolean::True)
        );
        for definition in [&oauth, &api_key, &basic] {
            let request = GrantRequest {
                additional: BTreeMap::new(),
                grant_type: definition.grant_type.clone(),
                requested_scopes: Vec::new(),
            };
            definition
                .handler
                .as_ref()
                .expect("handler")
                .grant(&request, &context(definition.grant_type.clone()))
                .await
                .expect("issued credential");
        }

        let cases = [
            (
                &oauth,
                headers("AEP-Authorization", "Bearer oauth-secret"),
                "oauth-1",
            ),
            (&api_key, headers("X-API-Key", "api-secret"), "api-1"),
            (
                &basic,
                headers(
                    header::AUTHORIZATION.as_str(),
                    &format!("Basic {}", STANDARD.encode("agent:basic-secret")),
                ),
                "basic-1",
            ),
        ];
        for (definition, headers, credential_id) in cases {
            let input = CredentialAuthenticationInput {
                headers,
                now: now(),
            };
            let principal = definition
                .handler
                .as_ref()
                .expect("handler")
                .authenticate(&input)
                .await
                .expect("authentication")
                .expect("principal");
            assert_eq!(
                principal.authentication_kind,
                AuthenticationKind::SessionCredential
            );
            assert_eq!(principal.credential_id.as_deref(), Some(credential_id));
        }

        oauth
            .handler
            .as_ref()
            .expect("handler")
            .revoke(
                &RevokeRequest {
                    additional: BTreeMap::new(),
                    all_grant_types: None,
                    credential_id: Some("oauth-1".to_owned()),
                    grant_type: Some(GrantType::OAuthBearer),
                },
                &context(GrantType::OAuthBearer),
            )
            .await
            .expect("revoke");
        assert!(
            oauth
                .handler
                .as_ref()
                .expect("handler")
                .authenticate(&CredentialAuthenticationInput {
                    headers: headers(header::AUTHORIZATION.as_str(), "Bearer oauth-secret"),
                    now: now(),
                })
                .await
                .expect("authentication")
                .is_none()
        );

        basic
            .handler
            .as_ref()
            .expect("handler")
            .revoke(
                &RevokeRequest {
                    additional: BTreeMap::new(),
                    all_grant_types: None,
                    credential_id: None,
                    grant_type: Some(GrantType::Basic),
                },
                &context(GrantType::Basic),
            )
            .await
            .expect("grant-type revoke");
        assert!(
            basic
                .handler
                .as_ref()
                .expect("handler")
                .authenticate(&CredentialAuthenticationInput {
                    headers: headers(
                        header::AUTHORIZATION.as_str(),
                        &format!("Basic {}", STANDARD.encode("agent:basic-secret")),
                    ),
                    now: now(),
                })
                .await
                .expect("authentication")
                .is_none()
        );
        assert!(
            api_key
                .handler
                .as_ref()
                .expect("handler")
                .authenticate(&CredentialAuthenticationInput {
                    headers: headers("X-API-Key", "api-secret"),
                    now: now() + Duration::hours(2),
                })
                .await
                .expect("authentication")
                .is_none()
        );
    });
}

#[test]
fn rejects_invalid_api_key_configuration_and_issued_header() {
    block_on(async {
        let store = Arc::new(MemoryServiceCredentialStore::default());
        let duplicate = GrantTypeConfig {
            additional: BTreeMap::from([(
                "header_names".to_owned(),
                json!(["X-API-Key", "x-api-key"]),
            )]),
            supports_per_credential_revoke: None,
        };
        let issue = Arc::new(|_: GrantRequest, context: GrantContext| {
            async move {
                Ok(ApiKeyGrantResponse {
                    additional: BTreeMap::new(),
                    api_key: "api-secret".to_owned(),
                    credential_id: "api-1".to_owned(),
                    expires_at: expiration(context.now),
                    header: "other-key".to_owned(),
                    scopes: Vec::new(),
                })
            }
            .boxed()
        });
        assert!(
            stored_api_key_grant_type(StoredApiKeyGrantTypeOptions {
                config: duplicate,
                issue: issue.clone(),
                store: store.clone(),
            })
            .is_err()
        );
        let definition = stored_api_key_grant_type(StoredApiKeyGrantTypeOptions {
            config: GrantTypeConfig {
                additional: BTreeMap::from([("header_names".to_owned(), json!(["x-api-key"]))]),
                supports_per_credential_revoke: None,
            },
            issue,
            store,
        })
        .expect("definition");
        assert!(
            definition
                .handler
                .expect("handler")
                .grant(
                    &GrantRequest {
                        additional: BTreeMap::new(),
                        grant_type: GrantType::ApiKey,
                        requested_scopes: Vec::new(),
                    },
                    &context(GrantType::ApiKey),
                )
                .await
                .is_err()
        );
    });
}

#[test]
fn rejects_reassigned_credential_identifiers_and_wrong_api_key_carriers() {
    block_on(async {
        let store = MemoryServiceCredentialStore::default();
        let record = api_key_record("first-secret");
        store.save(record.clone()).await.expect("saved credential");
        let mut reassigned = record;
        reassigned.credential = BuiltInGrantResponse::ApiKey(ApiKeyGrantResponse {
            api_key: "second-secret".to_owned(),
            ..api_key_response("second-secret")
        });
        assert!(store.save(reassigned).await.is_err());

        let input = CredentialAuthenticationInput {
            headers: headers("Service-API-Key", "first-secret"),
            now: now(),
        };
        assert!(
            store
                .has_presentation(&GrantType::ApiKey, &input)
                .await
                .expect("presentation")
        );
        assert!(
            store
                .authenticate(&GrantType::ApiKey, &input)
                .await
                .expect("authentication")
                .is_none()
        );
    });
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_788_177_600).expect("time")
}

fn expiration(created_at: OffsetDateTime) -> String {
    (created_at + Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("expiration")
}

fn context(grant_type: GrantType) -> GrantContext {
    GrantContext {
        agent_did: "did:web:agent.example".to_owned(),
        enrollment: EnrollmentRecord {
            agent_did: "did:web:agent.example".to_owned(),
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

fn headers(name: &str, value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::HeaderName::try_from(name).expect("header name"),
        HeaderValue::try_from(value).expect("header value"),
    );
    headers
}

fn api_key_response(secret: &str) -> ApiKeyGrantResponse {
    ApiKeyGrantResponse {
        additional: BTreeMap::new(),
        api_key: secret.to_owned(),
        credential_id: "credential-1".to_owned(),
        expires_at: expiration(now()),
        header: "x-api-key".to_owned(),
        scopes: Vec::new(),
    }
}

fn api_key_record(secret: &str) -> ServiceCredentialRecord {
    ServiceCredentialRecord {
        agent_did: "did:web:agent.example".to_owned(),
        created_at: now(),
        credential: BuiltInGrantResponse::ApiKey(api_key_response(secret)),
        credential_id: "credential-1".to_owned(),
        expires_at: now() + Duration::hours(1),
        grant_type: GrantType::ApiKey,
    }
}
