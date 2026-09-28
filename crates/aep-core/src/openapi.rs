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

/// How an Agent must treat the security an operation resolves to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenApiSecurityDisposition {
    Public,
    OptionalAnonymous,
    Required,
    Alternatives,
    AllRequired,
    FallbackLiveChallenge,
}

impl OpenApiSecurityDisposition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::OptionalAnonymous => "optional-anonymous",
            Self::Required => "required",
            Self::Alternatives => "alternatives",
            Self::AllRequired => "all-required",
            Self::FallbackLiveChallenge => "fallback-live-challenge",
        }
    }
}

/// The resolved security for one operation.
///
/// `satisfiable` lists the complete requirement objects the Agent can satisfy, each as the scheme
/// names it must present together. It is empty unless the disposition selects credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiSecurityResolution {
    pub disposition: OpenApiSecurityDisposition,
    pub satisfiable: Vec<Vec<String>>,
}

/// Resolves the effective security for one operation (CORE-OAS-011/013/014/015).
///
/// Operation-level security replaces the root value rather than adding to it, an empty list makes
/// the operation public, an empty requirement object is an anonymous alternative, several
/// requirement objects are alternatives, and several schemes inside one object are compound. An
/// Agent that cannot satisfy every member of a compound requirement treats that requirement as
/// unsupported and never reduces it to the members it does support, so the requirements reported
/// as satisfiable are always whole requirement objects.
#[must_use]
pub fn resolve_openapi_security(
    root: Option<&[Vec<String>]>,
    operation: Option<&[Vec<String>]>,
    supported_schemes: &[String],
) -> OpenApiSecurityResolution {
    let effective = operation.or(root).unwrap_or(&[]);
    if effective.is_empty() {
        return OpenApiSecurityResolution {
            disposition: OpenApiSecurityDisposition::Public,
            satisfiable: Vec::new(),
        };
    }
    if effective.iter().any(Vec::is_empty) {
        return OpenApiSecurityResolution {
            disposition: OpenApiSecurityDisposition::OptionalAnonymous,
            satisfiable: Vec::new(),
        };
    }
    let satisfiable: Vec<Vec<String>> = effective
        .iter()
        .filter(|requirement| {
            requirement
                .iter()
                .all(|scheme| supported_schemes.contains(scheme))
        })
        .cloned()
        .collect();
    let Some(only) = satisfiable.first() else {
        return OpenApiSecurityResolution {
            disposition: OpenApiSecurityDisposition::FallbackLiveChallenge,
            satisfiable: Vec::new(),
        };
    };
    let disposition = if effective.len() > 1 {
        OpenApiSecurityDisposition::Alternatives
    } else if only.len() > 1 {
        OpenApiSecurityDisposition::AllRequired
    } else {
        OpenApiSecurityDisposition::Required
    };
    OpenApiSecurityResolution {
        disposition,
        satisfiable,
    }
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
    let development_origin = allow_insecure_loopback
        && final_inspect_url.scheme() == "http"
        && final_inspect_url.host_str().is_some_and(is_loopback_host);
    if (final_inspect_url.scheme() != "https" && !development_origin)
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

/// Reports whether a URL host is one of the three loopback names that admit plaintext HTTP.
///
/// CORE-OAS-003 spells the exception syntactically: `localhost`, `127.0.0.1`, or `[::1]` and
/// nothing else. A name that happens to resolve to a loopback address, and any other address in
/// `127.0.0.0/8`, does not qualify.
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
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
