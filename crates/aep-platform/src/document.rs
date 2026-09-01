use std::{collections::BTreeMap, time::Duration};

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use url::Url;

use crate::{
    DidDocument, DidVerificationMethod, DiscoveryDocument, DiscoveryEndpoints, DiscoveryHttp,
    DiscoveryIdentity, DiscoveryOptions, DiscoveryPlatform, DiscoverySigning, IdentityRecord,
    PlatformError,
};

const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const DID_PLACEHOLDER: &str = "{agent_did_id}";
const DID_COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub fn create_service_scoped_agent_did(
    host: &str,
    path_prefix: &str,
    agent_did_id: &str,
) -> Result<String, PlatformError> {
    let url = Url::parse(&format!("https://{host}"))?;
    if host.is_empty()
        || agent_did_id.is_empty()
        || url.host_str().is_none()
        || url.as_str() != format!("https://{host}/")
    {
        return Err(PlatformError::InvalidConfiguration(
            "AEP Platform DID host or Agent DID identifier is invalid".to_owned(),
        ));
    }
    let mut parts = vec!["did".to_owned(), "web".to_owned(), encode_component(host)];
    for part in path_prefix.trim_matches('/').split('/') {
        if !part.is_empty() {
            parts.push(encode_component(part));
        }
    }
    parts.push(encode_component(agent_did_id));
    Ok(parts.join(":"))
}

pub fn create_did_document(
    identity: &IdentityRecord,
    method: DidVerificationMethod,
) -> Result<DidDocument, PlatformError> {
    validate_identity_record(identity)?;
    if method.id != identity.key_id
        || method.controller != identity.agent_did
        || method.method_type.is_empty()
        || !method.public_key_jwk.is_object()
    {
        return Err(PlatformError::InvalidConfiguration(
            "AEP Platform DID verification method does not match the managed identity".to_owned(),
        ));
    }
    Ok(DidDocument {
        context: vec![DID_CONTEXT.to_owned()],
        assertion_method: vec![method.id.clone()],
        authentication: vec![method.id.clone()],
        capability_invocation: vec![method.id.clone()],
        id: identity.agent_did.clone(),
        verification_method: vec![method],
    })
}

pub(crate) fn create_discovery_document(
    options: &DiscoveryOptions,
    did_url_template: &str,
    hosted_verification: bool,
    signing_algorithms: Vec<aep_core::SigningAlgorithm>,
    default_lifetime: Duration,
) -> Result<DiscoveryDocument, PlatformError> {
    for (name, path) in [
        ("endpoint base", options.endpoint_base.as_str()),
        ("lifecycle", options.lifecycle_endpoint.as_str()),
        ("list", options.list_endpoint.as_str()),
        ("provision", options.provision_endpoint.as_str()),
        ("sign", options.sign_endpoint.as_str()),
    ] {
        validate_endpoint_path(name, path)?;
    }
    let hosted_verification_endpoint = match (
        hosted_verification,
        options.hosted_verification_endpoint.as_deref(),
    ) {
        (true, Some(path)) => {
            validate_endpoint_path("hosted verification", path)?;
            Some(path.to_owned())
        }
        (true, None) => {
            return Err(PlatformError::InvalidConfiguration(
                "AEP Platform hosted verification endpoint is required".to_owned(),
            ));
        }
        (false, None) => None,
        (false, Some(_)) => {
            return Err(PlatformError::InvalidConfiguration(
                "AEP Platform hosted verification endpoint requires hosted verification".to_owned(),
            ));
        }
    };
    if options.platform_name.is_empty() {
        return Err(PlatformError::InvalidConfiguration(
            "AEP Platform name is required".to_owned(),
        ));
    }
    if options
        .platform_did
        .as_ref()
        .is_some_and(|did| !is_did(did))
    {
        return Err(PlatformError::InvalidConfiguration(
            "AEP Platform DID must be a DID".to_owned(),
        ));
    }
    render_did_url(did_url_template, "validation")?;
    Ok(DiscoveryDocument {
        aep_version: aep_core::VERSION.to_owned(),
        endpoints: DiscoveryEndpoints {
            additional: BTreeMap::new(),
            hosted_verification: hosted_verification_endpoint,
            lifecycle: options.lifecycle_endpoint.clone(),
            list: options.list_endpoint.clone(),
            provision: options.provision_endpoint.clone(),
            sign: options.sign_endpoint.clone(),
        },
        http: DiscoveryHttp {
            additional: BTreeMap::new(),
            endpoint_base: options.endpoint_base.clone(),
        },
        identity: DiscoveryIdentity {
            additional: BTreeMap::new(),
            did_methods: vec!["did:web".to_owned()],
            did_url_template: did_url_template.to_owned(),
        },
        platform: DiscoveryPlatform {
            additional: BTreeMap::new(),
            did: options.platform_did.clone(),
            hosted_verification,
            name: options.platform_name.clone(),
        },
        signing: DiscoverySigning {
            additional: BTreeMap::new(),
            algorithms: signing_algorithms,
            default_lifetime_seconds: default_lifetime.as_secs().to_string(),
        },
        additional: BTreeMap::new(),
    })
}

pub(crate) fn render_did_url(template: &str, agent_did_id: &str) -> Result<String, PlatformError> {
    if template.matches(DID_PLACEHOLDER).count() != 1 {
        return Err(PlatformError::InvalidConfiguration(
            "AEP Platform DID URL template must contain one {agent_did_id} placeholder".to_owned(),
        ));
    }
    let rendered = template.replace(DID_PLACEHOLDER, &encode_component(agent_did_id));
    let url = Url::parse(&rendered)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(PlatformError::InvalidConfiguration(
            "AEP Platform DID URL template must render an absolute HTTPS URL".to_owned(),
        ));
    }
    Ok(rendered)
}

pub(crate) fn validate_identity_record(identity: &IdentityRecord) -> Result<(), PlatformError> {
    if identity.agent_did.is_empty()
        || identity.agent_did_id.is_empty()
        || identity.agent_identity_id.is_empty()
        || identity.did_document_url.is_empty()
        || identity.key_id.is_empty()
        || identity.principal.is_empty()
        || identity.service_did.is_empty()
        || identity.signing_algorithms.is_empty()
    {
        return Err(PlatformError::Store(
            "AEP Platform identity store received an invalid record".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn is_did(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("did:") else {
        return false;
    };
    let Some((method, identifier)) = rest.split_once(':') else {
        return false;
    };
    !method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && !identifier.is_empty()
        && !identifier.chars().any(char::is_whitespace)
}

pub(crate) fn is_absolute_https_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn validate_endpoint_path(name: &str, path: &str) -> Result<(), PlatformError> {
    let parsed = Url::parse(&format!("https://platform.invalid{path}"));
    if path.is_empty()
        || !path.starts_with('/')
        || path.starts_with("//")
        || parsed.is_err()
        || path.contains('?')
        || path.contains('#')
    {
        return Err(PlatformError::InvalidConfiguration(format!(
            "AEP Platform {name} endpoint must be an absolute path"
        )));
    }
    Ok(())
}

fn encode_component(value: &str) -> String {
    utf8_percent_encode(value, DID_COMPONENT).to_string()
}
