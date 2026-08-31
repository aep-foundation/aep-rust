use url::Url;

use crate::{CoreError, OpenApiTrailingSlash};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiPathMatchOptions {
    pub method: String,
    pub path: String,
    pub trailing_slash: OpenApiTrailingSlash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiPathMatch {
    pub method: String,
    pub template: String,
}

pub fn match_openapi_path(
    templates: &[String],
    options: &OpenApiPathMatchOptions,
) -> Result<OpenApiPathMatch, CoreError> {
    let method = options.method.to_ascii_uppercase();
    if method.is_empty() || options.path.is_empty() || options.path.contains('?') {
        return Err(CoreError::Invalid(
            "invalid OpenAPI operation target".to_owned(),
        ));
    }
    let request_segments = path_segments(&options.path, options.trailing_slash);
    let mut best: Option<(&str, Vec<u8>)> = None;
    let mut ambiguous = false;
    for template in templates {
        let template_segments = path_segments(template, options.trailing_slash);
        if template_segments.len() != request_segments.len() {
            continue;
        }
        let mut specificity = Vec::with_capacity(template_segments.len());
        let mut matched = true;
        for (template_segment, request_segment) in
            template_segments.iter().zip(request_segments.iter())
        {
            if template_segment.starts_with('{')
                && template_segment.ends_with('}')
                && template_segment.len() > 2
            {
                specificity.push(0);
            } else {
                specificity.push(1);
                if template_segment != request_segment {
                    matched = false;
                    break;
                }
            }
        }
        if !matched {
            continue;
        }
        match &best {
            None => {
                best = Some((template, specificity));
                ambiguous = false;
            }
            Some((_current, score)) if specificity.as_slice() > score.as_slice() => {
                best = Some((template, specificity));
                ambiguous = false;
            }
            Some((_current, score)) if specificity == *score => ambiguous = true,
            Some(_) => {}
        }
    }
    let Some((template, _score)) = best else {
        return Err(CoreError::Invalid(
            "OpenAPI operation is not documented".to_owned(),
        ));
    };
    if ambiguous {
        return Err(CoreError::Invalid(
            "ambiguous OpenAPI path templates".to_owned(),
        ));
    }
    Ok(OpenApiPathMatch {
        method,
        template: template.to_owned(),
    })
}

pub fn resolve_openapi_url(
    final_inspect_url: &Url,
    reference: &str,
    allow_insecure_loopback: bool,
) -> Result<Url, CoreError> {
    if final_inspect_url.scheme() != "https"
        || final_inspect_url.host_str().is_none()
        || !final_inspect_url.username().is_empty()
        || final_inspect_url.password().is_some()
        || final_inspect_url.fragment().is_some()
    {
        return Err(CoreError::Invalid(
            "invalid final AEP Inspect URL".to_owned(),
        ));
    }
    let resolved = final_inspect_url.join(reference)?;
    if !resolved.username().is_empty()
        || resolved.password().is_some()
        || resolved.fragment().is_some()
        || resolved.host_str().is_none()
    {
        return Err(CoreError::Invalid("invalid AEP OpenAPI URL".to_owned()));
    }
    let secure = resolved.scheme() == "https";
    let allowed_loopback = allow_insecure_loopback
        && resolved.scheme() == "http"
        && resolved.host_str().is_some_and(is_loopback_host);
    if !secure && !allowed_loopback {
        return Err(CoreError::Invalid(
            "AEP OpenAPI URL requires HTTPS".to_owned(),
        ));
    }
    Ok(resolved)
}

fn path_segments(path: &str, trailing_slash: OpenApiTrailingSlash) -> Vec<&str> {
    let path = if trailing_slash == OpenApiTrailingSlash::Equivalent && path != "/" {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };
    path.strip_prefix('/').unwrap_or(path).split('/').collect()
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_the_most_specific_template() {
        let matched = match_openapi_path(
            &["/items/{id}".to_owned(), "/items/current".to_owned()],
            &OpenApiPathMatchOptions {
                method: "get".to_owned(),
                path: "/items/current".to_owned(),
                trailing_slash: OpenApiTrailingSlash::Strict,
            },
        )
        .expect("operation match");
        assert_eq!(matched.template, "/items/current");
    }

    #[test]
    fn handles_trailing_slashes_and_ambiguous_templates() {
        let matched = match_openapi_path(
            &["/items/{id}".to_owned()],
            &OpenApiPathMatchOptions {
                method: "post".to_owned(),
                path: "/items/one/".to_owned(),
                trailing_slash: OpenApiTrailingSlash::Equivalent,
            },
        )
        .expect("equivalent trailing slash");
        assert_eq!(matched.method, "POST");
        assert!(
            match_openapi_path(
                &["/items/{id}".to_owned(), "/items/{name}".to_owned()],
                &OpenApiPathMatchOptions {
                    method: "GET".to_owned(),
                    path: "/items/one".to_owned(),
                    trailing_slash: OpenApiTrailingSlash::Strict,
                },
            )
            .is_err()
        );
        assert!(
            match_openapi_path(
                &["/items/{id}".to_owned()],
                &OpenApiPathMatchOptions {
                    method: "GET".to_owned(),
                    path: "/other/one".to_owned(),
                    trailing_slash: OpenApiTrailingSlash::Strict,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn resolves_only_safe_openapi_urls() {
        let inspect = Url::parse("https://service.example/.well-known/aep").expect("Inspect URL");
        assert_eq!(
            resolve_openapi_url(&inspect, "/openapi.json", false)
                .expect("resolved OpenAPI URL")
                .as_str(),
            "https://service.example/openapi.json"
        );
        assert!(
            resolve_openapi_url(&inspect, "http://service.example/openapi.json", false).is_err()
        );
        let loopback = Url::parse("https://127.0.0.1/.well-known/aep").expect("Inspect URL");
        assert!(resolve_openapi_url(&loopback, "http://127.0.0.1/openapi.json", true).is_ok());
    }
}
