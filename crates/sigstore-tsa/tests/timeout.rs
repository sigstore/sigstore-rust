#![cfg(feature = "client")]

use sigstore_tsa::{Error, TimestampClient};
use sigstore_types::SignatureBytes;
use std::time::Duration;
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

#[tokio::test]
async fn request_timeout_covers_stalled_headers_and_body() {
    for send_headers in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if send_headers {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                    .await
                    .unwrap();
            }
            std::future::pending::<()>().await;
            drop(stream);
        });
        let client = TimestampClient::builder(url)
            .with_http_client(
                sigstore_tsa::reqwest::Client::builder()
                    .timeout(Duration::from_millis(100))
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let signature = SignatureBytes::from_bytes(b"signature");
        let result = timeout(
            Duration::from_secs(3),
            client.timestamp_signature(&signature),
        )
        .await;
        server.abort();
        assert!(matches!(
            result.expect("request hung"),
            Err(Error::Transport(_))
        ));
    }
}

/// A non-success HTTP status is reported with its code, apart from
/// transport failures.
#[tokio::test]
async fn error_status_is_reported_with_its_code() {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
        stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let client = TimestampClient::new(url).unwrap();
    let result = client
        .timestamp_signature(&SignatureBytes::from_bytes(b"signature"))
        .await;
    server.await.unwrap();
    assert!(
        matches!(result, Err(Error::Status { status: 503, .. })),
        "unexpected result: {result:?}"
    );
}
