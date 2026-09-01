use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::validation::deserialize_optional_non_null;

pub type AdditionalMembers = BTreeMap<String, Value>;

macro_rules! closed_string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        pub enum $name {
            $(#[serde(rename = $value)] $variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }
    };
}

macro_rules! extensible_string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub enum $name {
            $($variant),+,
            Other(String),
        }

        impl $name {
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $value),+,
                    Self::Other(value) => value,
                }
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                match value {
                    $($value => Self::$variant),+,
                    other => Self::Other(other.to_owned()),
                }
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::from(value.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Ok(Self::from(String::deserialize(deserializer)?))
            }
        }
    };
}

extensible_string_enum!(Command {
    Inspect => "inspect",
    Enroll => "enroll",
    Grant => "grant",
    Revoke => "revoke",
    Status => "status",
});

closed_string_enum!(AssertionOperation {
    Enroll => "enroll",
    Grant => "grant",
    Revoke => "revoke",
    Status => "status",
    Authenticate => "authenticate",
});

extensible_string_enum!(SigningAlgorithm {
    EdDsa => "EdDSA",
    Es256 => "ES256",
});

extensible_string_enum!(GrantType {
    OAuthBearer => "oauth-bearer",
    ApiKey => "api-key",
    Basic => "basic",
});

extensible_string_enum!(AuthenticationMethod {
    AepJwt => "aep-jwt",
    OAuthBearer => "oauth-bearer",
    ApiKey => "api-key",
    Basic => "basic",
});

extensible_string_enum!(Binding { Http => "http" });
extensible_string_enum!(IdentityMethod { DidWeb => "did:web" });

extensible_string_enum!(ClaimName {
    ContactAddressPrimary => "contact.address.primary",
    ContactEmail => "contact.email",
    ContactMobile => "contact.mobile",
    PersonBirthdate => "person.birthdate",
    PersonFirstName => "person.first_name",
    PersonLastName => "person.last_name",
    PersonUsername => "person.username",
});

extensible_string_enum!(ErrorCode {
    EnrollmentFailed => "enrollment_failed",
    InvalidRequest => "invalid_request",
    NotRecognized => "not_recognized",
    IdentitySuspended => "identity_suspended",
    IdentityTerminated => "identity_terminated",
    IdentityUnavailable => "identity_unavailable",
    VerificationPending => "verification_pending",
    VerificationTimeout => "verification_timeout",
    RequirementsUnmet => "requirements_unmet",
    RateLimited => "rate_limited",
    UnsupportedGrantType => "unsupported_grant_type",
    IdempotencyConflict => "idempotency_conflict",
    AuthenticationRequired => "authentication_required",
    UnsupportedAuthenticationMethod => "unsupported_authentication_method",
    InsufficientScope => "insufficient_scope",
});

closed_string_enum!(EnrollmentDecisionStatus {
    Active => "active",
    Pending => "pending",
    Rejected => "rejected",
});

pub type EnrollmentStatus = EnrollmentDecisionStatus;

closed_string_enum!(AgentStatus {
    Active => "active",
    Pending => "pending",
    Rejected => "rejected",
    Suspended => "suspended",
    Terminated => "terminated",
    Unavailable => "unavailable",
});

closed_string_enum!(StringBoolean { True => "true", False => "false" });
closed_string_enum!(OpenApiTrailingSlash { Strict => "strict", Equivalent => "equivalent" });
closed_string_enum!(AuthorizationCarrier {
    Standard => "Authorization",
    Dedicated => "AEP-Authorization",
});
closed_string_enum!(CredentialScheme { Aep => "AEP", Bearer => "Bearer", Basic => "Basic" });

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authentication {
    pub methods: Vec<AuthenticationMethod>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Bindings {
    pub supported: Vec<Binding>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct InspectClaims {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<ClaimName>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferred: Vec<ClaimName>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional: Vec<ClaimName>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct GrantTypeConfig {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub supports_per_credential_revoke: Option<StringBoolean>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Commands {
    pub supported: Vec<Command>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<GrantType>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub grant_types_config: BTreeMap<String, GrantTypeConfig>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CoreConfiguration {
    pub signing_algorithms: Vec<SigningAlgorithm>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Extensions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported: Vec<String>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenApiPathMatching {
    pub trailing_slash: OpenApiTrailingSlash,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenApiReference {
    pub url: String,
    pub path_matching: OpenApiPathMatching,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct HttpConfiguration {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub endpoint_base: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub openapi: Option<OpenApiReference>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Identity {
    pub methods: Vec<IdentityMethod>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct ServiceIdentity {
    pub did: String,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct InspectDocument {
    pub aep_version: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub authentication: Option<Authentication>,
    pub bindings: Bindings,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub claims: Option<InspectClaims>,
    pub commands: Commands,
    pub core: CoreConfiguration,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub extensions: Option<Extensions>,
    pub http: HttpConfiguration,
    pub identity: Identity,
    pub service: ServiceIdentity,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct ContactAddressPrimary {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub city: Option<String>,
    pub country: String,
    pub first_name: String,
    pub last_name: String,
    pub line1: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub line2: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub line3: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub postcode: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub region: Option<String>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct ClaimValues {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        rename = "contact.address.primary",
        skip_serializing_if = "Option::is_none"
    )]
    pub contact_address_primary: Option<ContactAddressPrimary>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        rename = "contact.email",
        skip_serializing_if = "Option::is_none"
    )]
    pub contact_email: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        rename = "contact.mobile",
        skip_serializing_if = "Option::is_none"
    )]
    pub contact_mobile: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        rename = "person.birthdate",
        skip_serializing_if = "Option::is_none"
    )]
    pub person_birthdate: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        rename = "person.first_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub person_first_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        rename = "person.last_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub person_last_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        rename = "person.username",
        skip_serializing_if = "Option::is_none"
    )]
    pub person_username: Option<String>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct EnrollRequest {
    pub agent_did: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub claims: Option<ClaimValues>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub idempotency_key: Option<String>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

fn owner_action_is_not_true(value: &Option<StringBoolean>) -> bool {
    !matches!(value, Some(StringBoolean::True))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EnrollResponse {
    pub status: AgentStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "owner_action_is_not_true"
    )]
    pub owner_action_required: Option<StringBoolean>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_pending: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub requirements_pending: Option<Vec<String>>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StatusResponse {
    pub status: AgentStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "owner_action_is_not_true"
    )]
    pub owner_action_required: Option<StringBoolean>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_pending: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub requirements_pending: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub since: Option<String>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GrantRequest {
    pub grant_type: GrantType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_scopes: Vec<String>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct RevokeRequest {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub grant_type: Option<GrantType>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub all_grant_types: Option<StringBoolean>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeResponse {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct IdempotencyMetadata {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub agent_did: Option<String>,
    pub idempotency_key: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub first_body_hash: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub second_body_hash: Option<String>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct OpenApiAepSecurityScheme {
    #[serde(rename = "x-aep-authentication-method")]
    pub authentication_method: AuthenticationMethod,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ClientAssertionClaims {
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub jti: String,
    pub op: AssertionOperation,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub resource: Option<String>,
    pub sub: String,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: i64,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub detail: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub instance: Option<String>,
    pub code: ErrorCode,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "owner_action_is_not_true"
    )]
    pub owner_action_required: Option<StringBoolean>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub requirements_pending: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_pending: Option<Vec<String>>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

fn deserialize_nullable_scopes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct OAuthBearerGrantResponse {
    pub access_token: String,
    pub credential_id: String,
    pub expires_at: String,
    #[serde(default, deserialize_with = "deserialize_nullable_scopes")]
    pub scopes: Vec<String>,
    pub token_type: String,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ApiKeyGrantResponse {
    pub api_key: String,
    pub credential_id: String,
    pub expires_at: String,
    pub header: String,
    #[serde(default, deserialize_with = "deserialize_nullable_scopes")]
    pub scopes: Vec<String>,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BasicGrantResponse {
    pub credential_id: String,
    pub expires_at: String,
    pub password: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub realm: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_scopes")]
    pub scopes: Vec<String>,
    pub username: String,
    #[serde(flatten)]
    pub additional: AdditionalMembers,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BuiltInGrantResponse {
    OAuthBearer(OAuthBearerGrantResponse),
    ApiKey(ApiKeyGrantResponse),
    Basic(BasicGrantResponse),
}

impl BuiltInGrantResponse {
    pub fn grant_type(&self) -> GrantType {
        match self {
            Self::OAuthBearer(_) => GrantType::OAuthBearer,
            Self::ApiKey(_) => GrantType::ApiKey,
            Self::Basic(_) => GrantType::Basic,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedResourceAuthorization {
    pub carrier: AuthorizationCarrier,
    pub scheme: CredentialScheme,
    pub credentials: String,
}
