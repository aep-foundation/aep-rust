use std::net::IpAddr;

use http::Uri;
use url::Url;

use crate::TowerError;

pub(crate) fn validate_origin(
    origin: &Url,
    allow_insecure_loopback: bool,
) -> Result<(), TowerError> {
    let secure = origin.scheme() == "https";
    let loopback = allow_insecure_loopback
        && origin.scheme() == "http"
        && origin.host_str().is_some_and(is_loopback);
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

pub(crate) fn request_url(origin: &Url, uri: &Uri) -> Result<Url, TowerError> {
    let path = uri.path_and_query().map_or("/", |value| value.as_str());
    origin.join(path).map_err(TowerError::from)
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}
