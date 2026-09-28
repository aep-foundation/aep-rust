use http::Uri;
use url::Url;

use crate::TowerError;

pub(crate) fn validate_origin(
    origin: &Url,
    allow_insecure_loopback: bool,
) -> Result<(), TowerError> {
    let secure = origin.scheme() == "https";
    // CORE-OAS-003 spells the plaintext exception syntactically, so the shared core predicate is
    // the only definition of a loopback host: a name that merely resolves to 127.0.0.0/8 or ::1
    // does not qualify, and `[::1]` does.
    let loopback = allow_insecure_loopback
        && origin.scheme() == "http"
        && origin.host_str().is_some_and(aep_core::is_loopback_host);
    if (!secure && !loopback)
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(TowerError::InvalidConfiguration(
            "protected-resource origin must be an HTTPS origin".to_owned(),
        ));
    }
    Ok(())
}

/// Resolves a request target onto the configured protected-resource origin.
///
/// Only the target's path and query identify the resource on this Service. They are written onto
/// the configured origin rather than resolved against it as a relative reference, because a
/// target beginning with `//` is a network-path reference: resolving `//attacker.example/x`
/// against `https://service.example` yields `https://attacker.example/x`. That URL becomes the
/// `resource` an assertion is checked against under CORE-CA-016, so a caller able to move it onto
/// another origin could satisfy the check with an assertion bound to a resource elsewhere.
pub(crate) fn request_url(origin: &Url, uri: &Uri) -> Url {
    let mut url = origin.clone();
    url.set_path(uri.path());
    url.set_query(uri.query());
    url
}
