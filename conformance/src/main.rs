mod platform;
mod role;
mod shared;

use std::io::{self, BufRead as _, Write as _};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Deserialize)]
struct AdapterRequest {
    case: AdapterCase,
    expectation: String,
    profile: String,
    protocol_version: String,
    role: String,
    sequence: u64,
    vector: VectorMetadata,
}

#[derive(Debug, Deserialize)]
struct AdapterCase {
    expected: Map<String, Value>,
    input: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct VectorMetadata {
    category: String,
    drafts: Vec<String>,
    id: String,
    title: String,
}

#[derive(Serialize)]
struct AdapterResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    protocol_version: &'static str,
    sequence: u64,
    status: &'static str,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let role = std::env::args()
        .nth(1)
        .ok_or_else(|| "usage: aep-conformance agent|platform|service".to_owned())?;
    if !matches!(role.as_str(), "agent" | "platform" | "service") {
        return Err("usage: aep-conformance agent|platform|service".to_owned());
    }
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let request: AdapterRequest =
            serde_json::from_str(&line).map_err(|error| error.to_string())?;
        validate_request(&request, &role)?;
        let result = evaluate(&request).await;
        let response = match result {
            Ok(true) => AdapterResponse {
                message: None,
                protocol_version: "1",
                sequence: request.sequence,
                status: "passed",
            },
            Ok(false) => AdapterResponse {
                message: Some("Public Rust API result did not match the vector".to_owned()),
                protocol_version: "1",
                sequence: request.sequence,
                status: "failed",
            },
            Err(message) => AdapterResponse {
                message: Some(truncate(message, 1024)),
                protocol_version: "1",
                sequence: request.sequence,
                status: "failed",
            },
        };
        serde_json::to_writer(&mut stdout, &response).map_err(|error| error.to_string())?;
        writeln!(stdout).map_err(|error| error.to_string())?;
        stdout.flush().map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn validate_request(request: &AdapterRequest, role: &str) -> Result<(), String> {
    if request.protocol_version != "1" || request.role != role {
        return Err("adapter request does not match the process contract".to_owned());
    }
    if request.expectation != "required" && request.expectation != "optional" {
        return Err("adapter request has an unknown expectation".to_owned());
    }
    if request.profile.is_empty()
        || request.vector.category.is_empty()
        || request.vector.drafts.is_empty()
        || request.vector.title.is_empty()
    {
        return Err("adapter request metadata is incomplete".to_owned());
    }
    Ok(())
}

async fn evaluate(request: &AdapterRequest) -> Result<bool, String> {
    if request.role == "platform" {
        return platform::evaluate(request).await;
    }
    if let Some(result) = shared::evaluate(request)? {
        return Ok(result);
    }
    match request.role.as_str() {
        "agent" => shared::evaluate_agent(request).await,
        "service" => shared::evaluate_service(request).await,
        _ => Err(format!("unsupported role {}", request.role)),
    }
}

fn truncate(mut value: String, maximum: usize) -> String {
    if value.len() <= maximum {
        return value;
    }
    while !value.is_char_boundary(maximum) {
        value.remove(maximum);
    }
    value.truncate(maximum);
    value
}

fn input<T: serde::de::DeserializeOwned>(
    request: &AdapterRequest,
    name: &str,
) -> Result<T, String> {
    field(&request.case.input, name)
}

fn expected<T: serde::de::DeserializeOwned>(
    request: &AdapterRequest,
    name: &str,
) -> Result<T, String> {
    field(&request.case.expected, name)
}

fn field<T: serde::de::DeserializeOwned>(
    object: &Map<String, Value>,
    name: &str,
) -> Result<T, String> {
    let value = object
        .get(name)
        .ok_or_else(|| format!("required field {name:?} is missing"))?;
    serde_json::from_value(value.clone()).map_err(|error| format!("decode field {name:?}: {error}"))
}

fn object_value(object: &Map<String, Value>) -> Value {
    Value::Object(object.clone())
}
