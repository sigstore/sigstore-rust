use sigstore_rekor::{HashedRekordV2, RekorV2Client, RekorV2KeyDetails};
use sigstore_types::{DerCertificate, Sha256Hash, SignatureBytes};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::num::NonZeroU8;
use std::sync::mpsc;

const VALID_ENTRY: &str = r#"{
  "logIndex":"7",
  "logId":{"keyId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
  "kindVersion":{"kind":"hashedrekord","version":"0.0.2"},
  "integratedTime":"0",
  "inclusionPromise":null,
  "inclusionProof":{
    "logIndex":"7",
    "rootHash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "treeSize":"8",
    "hashes":[],
    "checkpoint":{"envelope":"example.com/log\n8\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n"}
  },
  "canonicalizedBody":"eyJzcGVjIjp7Imhhc2hlZFJla29yZFYwMDIiOnsiZGF0YSI6eyJkaWdlc3QiOiJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFPSJ9LCJzaWduYXR1cmUiOnsiY29udGVudCI6ImMybG5ibUYwZFhKbCIsInZlcmlmaWVyIjp7ImtleURldGFpbHMiOiJQS0lYX0VDRFNBX1AyNTZfU0hBXzI1NiIsIng1MDlDZXJ0aWZpY2F0ZSI6eyJyYXdCeXRlcyI6Ik1BQT0ifX19fX19"
}"#;

fn serve_once(status: &str, content_type: &str, body: &[u8]) -> (String, mpsc::Receiver<String>) {
    let status = status.to_string();
    let content_type = content_type.to_string();
    let body = body.to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = mpsc::channel();

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        request_tx
            .send(String::from_utf8_lossy(&request).into_owned())
            .unwrap();
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    });

    (format!("http://{address}"), request_rx)
}

fn request() -> HashedRekordV2 {
    HashedRekordV2::new_with_certificate(
        &Sha256Hash::from_bytes([1; 32]),
        &SignatureBytes::from_bytes(b"signature"),
        &DerCertificate::new(vec![0x30, 0x00]),
        RekorV2KeyDetails::PkixEcdsaP256Sha256,
    )
}

#[tokio::test]
async fn create_entry_returns_the_protobuf_entry_without_lossy_conversion() {
    let (url, received) = serve_once("201 Created", "application/json", VALID_ENTRY.as_bytes());
    let client = RekorV2Client::new(url);

    let entry = client.create_entry(request()).await.unwrap();

    assert_eq!(entry.log_index.value(), 7);
    assert_eq!(
        entry.log_id.key_id.as_str(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    );
    assert_eq!(entry.kind_version.kind, "hashedrekord");
    assert_eq!(entry.kind_version.version, "0.0.2");
    assert!(entry.integrated_time.is_none());
    assert!(entry.inclusion_promise.is_none());
    assert_eq!(entry.inclusion_proof.unwrap().tree_size, 8);
    assert!(received
        .recv()
        .unwrap()
        .starts_with("POST /api/v2/log/entries "));
}

#[tokio::test]
async fn create_entry_rejects_malformed_or_incomplete_v2_responses() {
    for invalid in [
        VALID_ENTRY.replace("\"logIndex\":\"7\"", "\"logIndex\":\"invalid\""),
        VALID_ENTRY.replace("\"version\":\"0.0.2\"", "\"version\":\"0.0.1\""),
        VALID_ENTRY.replace("\"integratedTime\":\"0\"", "\"integratedTime\":\"1\""),
        VALID_ENTRY.replace("\"inclusionProof\":{", "\"inclusionProofMissing\":{"),
        VALID_ENTRY
            .replace(
                "\"checkpoint\":{\"envelope\":\"example.com/log",
                "\"checkpoint\":{\"envelope\":\"",
            )
            .replace(
                "\\n8\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\\n\\n\"}",
                "\"}",
            ),
    ] {
        let (url, received) = serve_once("201 Created", "application/json", invalid.as_bytes());
        let error = RekorV2Client::new(url)
            .create_entry(request())
            .await
            .unwrap_err();
        received.recv().unwrap();
        assert!(
            error.to_string().contains("Invalid response"),
            "unexpected error: {error}"
        );
    }
}

#[tokio::test]
async fn create_entry_rejects_a_response_for_a_different_submission() {
    let (url, _received) = serve_once("201 Created", "application/json", VALID_ENTRY.as_bytes());
    let different = HashedRekordV2::new_with_certificate(
        &Sha256Hash::from_bytes([2; 32]),
        &SignatureBytes::from_bytes(b"other signature"),
        &DerCertificate::new(vec![0x30, 0x00]),
        RekorV2KeyDetails::PkixEcdsaP256Sha256,
    );
    let error = RekorV2Client::new(url)
        .create_entry(different)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match the submitted entry"));
}

#[tokio::test]
async fn create_entry_ignores_unauthenticated_duplicate_proof_fields() {
    let response = VALID_ENTRY
        .replace(
            "\"logIndex\":\"7\",\n    \"rootHash\"",
            "\"logIndex\":\"0\",\n    \"rootHash\"",
        )
        .replace("\"treeSize\":\"8\"", "\"treeSize\":\"1\"");
    let (url, _received) = serve_once("201 Created", "application/json", response.as_bytes());

    let entry = RekorV2Client::new(url)
        .create_entry(request())
        .await
        .unwrap();
    assert_eq!(entry.log_index.value(), 7);
    assert_eq!(entry.inclusion_proof.unwrap().log_index.value(), 0);
}

#[tokio::test]
async fn reads_v2_checkpoint_and_tile_storage_paths() {
    let (url, checkpoint_request) = serve_once(
        "200 OK",
        "application/octet-stream",
        b"example.com/log\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n\xe2\x80\x94 example.com/log AAAAAAA=\n",
    );
    let checkpoint = RekorV2Client::new(url).get_checkpoint().await.unwrap();
    assert_eq!(checkpoint.origin, "example.com/log");
    assert_eq!(checkpoint.tree_size, 1);
    assert!(checkpoint_request
        .recv()
        .unwrap()
        .starts_with("GET /api/v2/checkpoint "));

    let (url, tile_request) = serve_once("200 OK", "application/octet-stream", b"tile");
    let tile = RekorV2Client::new(url)
        .get_tile(2, 1_234_067, NonZeroU8::new(7))
        .await
        .unwrap();
    assert_eq!(tile.level, 2);
    assert_eq!(tile.index, 1_234_067);
    assert_eq!(tile.width, NonZeroU8::new(7));
    assert_eq!(tile.as_bytes(), b"tile");
    // C2SP spec example: every base-1000 group is zero-padded to 3 digits.
    assert!(tile_request
        .recv()
        .unwrap()
        .starts_with("GET /api/v2/tile/2/x001/x234/067.p/7 "));

    let (url, entries_request) = serve_once("200 OK", "application/octet-stream", b"entries");
    let entries = RekorV2Client::new(url)
        .get_entry_bundle(1, None)
        .await
        .unwrap();
    assert_eq!(entries.index, 1);
    assert_eq!(entries.width, None);
    assert_eq!(entries.as_bytes(), b"entries");
    assert!(entries_request
        .recv()
        .unwrap()
        .starts_with("GET /api/v2/tile/entries/001 "));
}
