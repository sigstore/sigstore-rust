use sigstore_fulcio::{Error, FulcioClient};
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
        let client = FulcioClient::builder(url)
            .with_timeout(Duration::from_millis(100))
            .build();
        let result = timeout(Duration::from_secs(3), client.get_configuration()).await;
        server.abort();
        assert!(matches!(result.expect("request hung"), Err(Error::Http(_))));
    }
}
