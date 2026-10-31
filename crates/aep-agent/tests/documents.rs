use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use aep_agent::{DocumentFallback, read_service_document};
use aep_core::{DocumentEnrollment, DocumentRepresentation, ServiceDocument};
use serde_json::json;

fn descriptor(url: String) -> ServiceDocument {
    ServiceDocument {
        id: "terms".into(),
        document_type: "terms_of_service".into(),
        title: "Terms".into(),
        enrollment: DocumentEnrollment::Required,
        representations: vec![
            DocumentRepresentation {
                media_type: "text/html".into(),
                url: "https://example.com/terms".into(),
            },
            DocumentRepresentation {
                media_type: "application/json".into(),
                url,
            },
        ],
    }
}

fn body() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"format":"aep-service-document","version":"1.0","id":"terms",
        "content":[{"type":"paragraph","text":"Exact service text."}]}),
    )
    .unwrap()
}

fn serve(
    response: Vec<u8>,
    delay: Duration,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/document", listener.local_addr().unwrap());
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (mut socket, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(error) => panic!("document test did not connect: {error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if socket.read(&mut byte).unwrap_or(0) == 0 {
                return;
            }
            request.push(byte[0]);
        }
        sender.send(String::from_utf8(request).unwrap()).unwrap();
        let prefix = if delay.is_zero() {
            0
        } else {
            response
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap()
                + 4
        };
        let _ = socket.write_all(&response[..prefix]);
        thread::sleep(delay);
        let _ = socket.write_all(&response[prefix..]);
        let _ = socket.shutdown(Shutdown::Write);
        let _ = socket.read(&mut [0]);
    });
    (url, receiver, handle)
}

fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[tokio::test]
async fn retrieves_anonymous_portable_content_and_keeps_html_fallback() {
    let (url, request, server) = serve(
        response(
            "200 OK",
            "Content-Type: application/json; charset=\"UTF-8\"\r\n",
            &body(),
        ),
        Duration::ZERO,
    );
    let result = read_service_document(&descriptor(url), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(result.document.is_some());
    assert_eq!(result.fallback, None);
    assert_eq!(result.web_url, "https://example.com/terms");
    let request = request.recv().unwrap().to_lowercase();
    assert!(request.starts_with("get /document http/1.1\r\n"));
    assert!(request.contains("accept: application/json\r\n"));
    for header in ["authorization:", "cookie:", "x-agent", "user-agent:"] {
        assert!(!request.contains(header));
    }
    server.join().unwrap();
    let mut html = descriptor("https://example.com/terms.json".into());
    html.representations.pop();
    let result = read_service_document(&html, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(result.fallback, Some(DocumentFallback::NotAdvertised));
    assert!(read_service_document(&html, Duration::ZERO).await.is_err());
    html.id.clear();
    assert!(
        read_service_document(&html, Duration::from_secs(1))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_unusable_responses_without_rendering_partial_documents() {
    let mut wrong_id: serde_json::Value = serde_json::from_slice(&body()).unwrap();
    wrong_id["id"] = json!("other");
    let mut unknown: serde_json::Value = serde_json::from_slice(&body()).unwrap();
    unknown["content"][0]["type"] = json!("future");
    let cases = vec![
        response("404 Not Found","Content-Type: application/json\r\n",&body()),
        response("302 Found","Location: http://127.0.0.1:1/target\r\n",&body()),
        response("200 OK","Content-Type: text/html\r\n",&body()),
        response("200 OK","Content-Type: application/json; charset=iso-8859-1\r\n",&body()),
        response("200 OK","Content-Type: application/json\r\nContent-Encoding: gzip\r\n",&body()),
        response("200 OK","Content-Type: application/json\r\n",b"\xff"),
        response("200 OK","Content-Type: application/json\r\n",b"{"),
        response("200 OK","Content-Type: application/json\r\n",&serde_json::to_vec(&wrong_id).unwrap()),
        response("200 OK","Content-Type: application/json\r\n",&serde_json::to_vec(&unknown).unwrap()),
        response("200 OK","Content-Type: application/json\r\n",&vec![b' ';(1<<20)+1]),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n".to_vec()
    ];
    for bytes in cases {
        let (url, request, server) = serve(bytes, Duration::ZERO);
        let result = read_service_document(&descriptor(url), Duration::from_secs(2))
            .await
            .unwrap();
        assert!(result.document.is_none());
        assert_eq!(
            result.fallback,
            Some(DocumentFallback::UnavailableOrUnsupported)
        );
        request.recv().unwrap();
        server.join().unwrap();
    }
}

#[tokio::test]
async fn bounds_waiting_and_allows_caller_cancellation() {
    let (url, request, server) = serve(
        response("200 OK", "Content-Type: application/json\r\n", &body()),
        Duration::from_millis(200),
    );
    let result = read_service_document(&descriptor(url), Duration::from_millis(50))
        .await
        .unwrap();
    assert_eq!(
        result.fallback,
        Some(DocumentFallback::UnavailableOrUnsupported)
    );
    request.recv().unwrap();
    server.join().unwrap();
    let (url, request, server) = serve(
        response("200 OK", "Content-Type: application/json\r\n", &body()),
        Duration::from_millis(200),
    );
    let task = tokio::spawn(async move {
        read_service_document(&descriptor(url), Duration::from_secs(10)).await
    });
    tokio::task::spawn_blocking(move || request.recv().unwrap())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    server.join().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/doc", listener.local_addr().unwrap());
    drop(listener);
    assert!(
        read_service_document(&descriptor(url), Duration::from_secs(1))
            .await
            .unwrap()
            .document
            .is_none()
    );
}
