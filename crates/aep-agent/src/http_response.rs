use http::{HeaderMap, HeaderName, HeaderValue, header};
use time::OffsetDateTime;

const CACHE_HEADERS: [HeaderName; 7] = [
    header::CACHE_CONTROL,
    header::AGE,
    header::DATE,
    header::EXPIRES,
    header::ETAG,
    header::LAST_MODIFIED,
    header::VARY,
];

pub(crate) fn cache_headers(
    response: &HeaderMap,
    prior: Option<&HeaderMap>,
    requested_at: OffsetDateTime,
    received_at: OffsetDateTime,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for name in CACHE_HEADERS {
        // A validation response has its own age and creation time, even when it omits them.
        let source = if response.contains_key(&name) || name == header::AGE || name == header::DATE
        {
            Some(response)
        } else {
            prior
        };
        if let Some(source) = source {
            for value in source.get_all(&name) {
                headers.append(name.clone(), value.clone());
            }
        }
    }
    // RFC 9111 age includes the request delay; cached_at remains the actual receipt time.
    if let Some(age) = age_seconds(&headers) {
        let delay = (received_at - requested_at).whole_seconds().max(0) as u64;
        let corrected = age.saturating_add(delay).to_string();
        if let Ok(value) = HeaderValue::from_str(&corrected) {
            headers.insert(header::AGE, value);
        }
    }
    headers
}

pub(crate) fn header_string(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    let values = headers
        .get_all(name)
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!values.is_empty()).then(|| values.join(", "))
}

pub(crate) fn cache_storable(headers: &HeaderMap) -> bool {
    cache_directives(headers).is_some_and(|directives| {
        !directives
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(b"no-store"))
    }) && !header_string(headers, header::VARY)
        .is_some_and(|value| value.split(',').any(|part| part.trim() == "*"))
}

pub(crate) fn cache_fresh(
    headers: &HeaderMap,
    cached_at: OffsetDateTime,
    now: OffsetDateTime,
) -> bool {
    if !cache_storable(headers) {
        return false;
    }
    let Some(directives) = cache_directives(headers) else {
        return false;
    };
    if directives
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(b"no-cache"))
    {
        return false;
    }
    let mut max_ages = directives
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(b"max-age"));
    let lifetime = match max_ages.next() {
        Some((_, value)) => {
            if max_ages.next().is_some() {
                return false;
            }
            let Some(seconds) = value.and_then(decimal_seconds) else {
                return false;
            };
            let Ok(seconds) = i64::try_from(seconds) else {
                return false;
            };
            time::Duration::seconds(seconds)
        }
        None => match headers.get(header::EXPIRES) {
            Some(_) => {
                let Some(expires) = date(headers, header::EXPIRES) else {
                    return false;
                };
                (expires - date(headers, header::DATE).unwrap_or(cached_at))
                    .max(time::Duration::ZERO)
            }
            None => time::Duration::seconds(300),
        },
    };
    let Some(age) = age_seconds(headers).and_then(|value| i64::try_from(value).ok()) else {
        return false;
    };
    let apparent_age =
        (cached_at - date(headers, header::DATE).unwrap_or(cached_at)).max(time::Duration::ZERO);
    let initial_age = apparent_age.max(time::Duration::seconds(age));
    let resident_age = (now - cached_at).max(time::Duration::ZERO);
    initial_age.saturating_add(resident_age) < lifetime
}

fn age_seconds(headers: &HeaderMap) -> Option<u64> {
    if !headers.contains_key(header::AGE) {
        return Some(0);
    }
    decimal_seconds(header_string(headers, header::AGE)?.trim().as_bytes())
}

fn decimal_seconds(value: &[u8]) -> Option<u64> {
    (!value.is_empty() && value.iter().all(u8::is_ascii_digit))
        .then(|| std::str::from_utf8(value).ok()?.parse().ok())
        .flatten()
}

fn date(headers: &HeaderMap, name: HeaderName) -> Option<OffsetDateTime> {
    httpdate::parse_http_date(headers.get(name)?.to_str().ok()?)
        .ok()
        .map(OffsetDateTime::from)
}

type Directive<'a> = (&'a [u8], Option<&'a [u8]>);

fn cache_directives(headers: &HeaderMap) -> Option<Vec<Directive<'_>>> {
    let mut result = Vec::new();
    for value in headers.get_all(header::CACHE_CONTROL) {
        let mut remaining = value.as_bytes().trim_ascii();
        while !remaining.is_empty() {
            if let Some(rest) = remaining.strip_prefix(b",") {
                remaining = rest.trim_ascii_start();
                continue;
            }
            let name = token(&mut remaining)?;
            let argument = if let Some(rest) = remaining.strip_prefix(b"=") {
                remaining = rest;
                Some(parameter_value(&mut remaining)?)
            } else {
                None
            };
            result.push((name, argument));
            remaining = remaining.trim_ascii_start();
            if !remaining.is_empty() {
                remaining = remaining.strip_prefix(b",")?.trim_ascii_start();
            }
        }
    }
    Some(result)
}

pub(crate) fn media_type_matches(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let mut remaining = value.as_bytes().trim_ascii();
    let Some((expected_type, expected_subtype)) = expected.split_once('/') else {
        return false;
    };
    let Some(actual_type) = token(&mut remaining) else {
        return false;
    };
    if !actual_type.eq_ignore_ascii_case(expected_type.as_bytes()) {
        return false;
    }
    let Some(rest) = remaining.strip_prefix(b"/") else {
        return false;
    };
    remaining = rest;
    let Some(subtype) = token(&mut remaining) else {
        return false;
    };
    if !subtype.eq_ignore_ascii_case(expected_subtype.as_bytes()) {
        return false;
    }
    remaining = remaining.trim_ascii_start();
    while !remaining.is_empty() {
        let Some(rest) = remaining.strip_prefix(b";") else {
            return false;
        };
        remaining = rest.trim_ascii_start();
        // RFC 9110 parameters permits an empty member after a semicolon.
        if remaining.is_empty() || remaining.starts_with(b";") {
            continue;
        }
        if token(&mut remaining).is_none() {
            return false;
        }
        let Some(rest) = remaining.strip_prefix(b"=") else {
            return false;
        };
        remaining = rest;
        if parameter_value(&mut remaining).is_none() {
            return false;
        }
        remaining = remaining.trim_ascii_start();
    }
    true
}

fn token<'a>(remaining: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = remaining
        .iter()
        .copied()
        .take_while(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
        .count();
    if length == 0 {
        return None;
    }
    let (value, rest) = remaining.split_at(length);
    *remaining = rest;
    Some(value)
}

fn parameter_value<'a>(remaining: &mut &'a [u8]) -> Option<&'a [u8]> {
    if !remaining.starts_with(b"\"") {
        return token(remaining);
    }
    let bytes = *remaining;
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let value = &remaining[1..index];
                *remaining = &remaining[index + 1..];
                return Some(value);
            }
            b'\\' => {
                index += 1;
                let byte = *bytes.get(index)?;
                if !(byte == b'\t' || (b' '..=b'~').contains(&byte) || byte >= 128) {
                    return None;
                }
            }
            b'\t' | b' ' | b'!' | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => {}
            _ => return None,
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_788_177_600).expect("timestamp")
    }

    fn headers(values: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in values {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("name"),
                HeaderValue::from_str(value).expect("value"),
            );
        }
        headers
    }

    #[test]
    fn media_types_follow_http_token_and_quoted_string_grammar() {
        for value in [
            "application/aep+json",
            "APPLICATION/AEP+JSON; charset=utf-8",
            " application/aep+json \t; charset=\"UTF-8\" ",
            "application/aep+json; note=\"a;b,c\\\"d\\\\e\"; other=token",
            "application/aep+json; empty=\"\"",
            "application/aep+json;; ;",
            "application/aep+json; note=\"é\"",
        ] {
            assert!(
                media_type_matches(&headers(&[("content-type", value)]), "application/aep+json"),
                "{value}"
            );
        }
        for value in [
            "",
            "application",
            "application/",
            "/aep+json",
            "text/plain",
            "application/aep+json garbage",
            "application/aep+json; charset",
            "application/aep+json; =utf-8",
            "application/aep+json; charset=",
            "application/aep+json; charset=\"unterminated",
            "application/aep+json; charset=\"dangling\\",
            "application/aep+json; charset=\"utf-8\"extra",
            "application/aep+json; charset =utf-8",
            "application/aep+json; charset= utf-8",
            "application/aep+json; charset=utf 8",
            "application/aep+json, text/plain",
        ] {
            assert!(
                !media_type_matches(&headers(&[("content-type", value)]), "application/aep+json"),
                "{value}"
            );
        }
        assert!(!media_type_matches(
            &HeaderMap::new(),
            "application/aep+json"
        ));
        assert!(!media_type_matches(
            &headers(&[
                ("content-type", "application/aep+json"),
                ("content-type", "application/aep+json")
            ]),
            "application/aep+json"
        ));
        let opaque = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            HeaderValue::from_bytes(b"\xff").expect("opaque"),
        )]);
        assert!(!media_type_matches(&opaque, "application/aep+json"));
        let quoted_opaque = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            HeaderValue::from_bytes(b"application/aep+json; note=\"\xff\"").expect("quoted bytes"),
        )]);
        assert!(media_type_matches(&quoted_opaque, "application/aep+json"));
    }

    #[test]
    fn cache_metadata_retains_only_cache_headers_and_replaces_repeated_fields() {
        let prior = headers(&[
            ("cache-control", "max-age=20"),
            ("cache-control", "no-cache"),
            ("etag", "\"one\""),
            ("last-modified", "Mon, 31 Aug 2026 11:00:00 GMT"),
            ("age", "999"),
            ("date", "Mon, 31 Aug 2026 11:00:00 GMT"),
        ]);
        let incoming = headers(&[
            ("cache-control", "max-age=60"),
            ("cache-control", "private"),
            ("set-cookie", "secret"),
            ("authorization", "Bearer secret"),
        ]);
        let updated = cache_headers(
            &incoming,
            Some(&prior),
            now(),
            now() + time::Duration::seconds(3),
        );
        assert_eq!(
            header_string(&updated, header::CACHE_CONTROL).as_deref(),
            Some("max-age=60, private")
        );
        assert_eq!(updated[header::ETAG], "\"one\"");
        assert!(updated.contains_key(header::LAST_MODIFIED));
        assert!(!updated.contains_key(header::DATE));
        assert_eq!(updated[header::AGE], "3");
        assert!(!updated.contains_key(header::SET_COOKIE));
        assert!(!updated.contains_key(header::AUTHORIZATION));
        assert!(cache_fresh(
            &updated,
            now() + time::Duration::seconds(3),
            now() + time::Duration::seconds(59)
        ));
        assert!(!cache_fresh(
            &updated,
            now() + time::Duration::seconds(3),
            now() + time::Duration::seconds(60)
        ));
    }

    #[test]
    fn cache_freshness_accounts_for_age_dates_expiry_and_default_lifetime() {
        let cases = [
            (headers(&[]), 299, true),
            (headers(&[]), 300, false),
            (
                headers(&[("cache-control", "max-age=300"), ("age", "299")]),
                0,
                true,
            ),
            (
                headers(&[("cache-control", "max-age=300"), ("age", "299")]),
                2,
                false,
            ),
            (
                headers(&[
                    ("cache-control", "max-age=300"),
                    ("date", "Mon, 31 Aug 2026 11:55:01 GMT"),
                ]),
                2,
                false,
            ),
            (
                headers(&[("expires", "Mon, 31 Aug 2026 12:00:01 GMT")]),
                2,
                false,
            ),
            (
                headers(&[
                    ("date", "Mon, 31 Aug 2026 12:00:00 GMT"),
                    ("expires", "Mon, 31 Aug 2026 12:00:10 GMT"),
                ]),
                9,
                true,
            ),
            (
                headers(&[
                    ("date", "Mon, 31 Aug 2026 12:00:30 GMT"),
                    ("expires", "Mon, 31 Aug 2026 12:00:40 GMT"),
                ]),
                10,
                false,
            ),
            (headers(&[("expires", "0")]), 0, false),
            (
                headers(&[("cache-control", "max-age=60"), ("expires", "0")]),
                0,
                true,
            ),
            (
                headers(&[
                    ("cache-control", "max-age=1"),
                    ("cache-control", "no-store"),
                ]),
                0,
                false,
            ),
            (
                headers(&[("cache-control", "max-age=60, no-cache=\"etag, date\"")]),
                0,
                false,
            ),
            (
                headers(&[("cache-control", "unknown=\"x,y\", max-age=\"60\"")]),
                59,
                true,
            ),
            (headers(&[("vary", "accept, *")]), 0, false),
            (headers(&[("age", "9223372036854775808")]), 0, false),
        ];
        for (metadata, elapsed, expected) in cases {
            assert_eq!(
                cache_fresh(&metadata, now(), now() + time::Duration::seconds(elapsed)),
                expected,
                "{metadata:?}"
            );
        }
        for control in [
            "max-age=1.5",
            "max-age=-1",
            "max-age=+1",
            "max-age=",
            "max-age=\"\"",
            "max-age=18446744073709551615",
            "max-age=1,max-age=2",
            "broken=\"",
            "bad@directive",
        ] {
            assert!(
                !cache_fresh(&headers(&[("cache-control", control)]), now(), now()),
                "{control}"
            );
        }
        for age in ["-1", "1.5", "18446744073709551616"] {
            assert!(
                !cache_fresh(&headers(&[("age", age)]), now(), now()),
                "{age}"
            );
        }
        assert!(cache_storable(&headers(&[(
            "cache-control",
            ", ,private, unknown=\"x,y\", "
        )])));
        assert!(!cache_storable(&headers(&[(
            "cache-control",
            "no-store=\"fields\""
        )])));
        assert!(!cache_storable(&HeaderMap::from_iter([(
            header::CACHE_CONTROL,
            HeaderValue::from_bytes(b"\xff").expect("opaque")
        )])));
    }
}
