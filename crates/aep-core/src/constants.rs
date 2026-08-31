use std::time::Duration;

use crate::ClaimName;

pub const VERSION: &str = "1.0";
pub const MEDIA_TYPE: &str = "application/aep+json";
pub const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
pub const AUTHORIZATION_SCHEME: &str = "AEP";
pub const AUTHORIZATION_HEADER: &str = "AEP-Authorization";
pub const WELL_KNOWN_PATH: &str = "/.well-known/aep";
pub const DEFAULT_HTTP_ENDPOINT_BASE: &str = "/aep/";
pub const MAX_AUTHENTICATION_METHODS: usize = 16;
pub const MAX_ASSERTION_LIFETIME: Duration = Duration::from_secs(300);
pub const RECOMMENDED_CLOCK_SKEW: Duration = Duration::from_secs(30);
pub const DEFAULT_INSPECT_FRESHNESS: Duration = Duration::from_secs(300);
pub const MINIMUM_IDEMPOTENCY_TTL: Duration = Duration::from_secs(3600);

pub fn registered_claims() -> Vec<ClaimName> {
    vec![
        ClaimName::ContactAddressPrimary,
        ClaimName::ContactEmail,
        ClaimName::ContactMobile,
        ClaimName::PersonBirthdate,
        ClaimName::PersonFirstName,
        ClaimName::PersonLastName,
        ClaimName::PersonUsername,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_each_registered_claim() {
        let claims = registered_claims();
        assert_eq!(claims.len(), 7);
        assert!(claims.contains(&ClaimName::ContactAddressPrimary));
    }
}
