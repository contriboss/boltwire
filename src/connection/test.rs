use super::*;

fn mem_conn(stream: tokio::io::DuplexStream) -> BoltConnection {
    BoltConnection {
        stream: Stream::Mem(stream),
        version: Version::new(5, 8),
        server_agent: None,
        connection_id: None,
        needs_reset: false,
        read_timeout: DEFAULT_READ_TIMEOUT,
    }
}

#[tokio::test]
async fn reader_skips_noop_keepalives() {
    let (client, mut server) = tokio::io::duplex(256);
    let mut conn = mem_conn(client);

    // Two NOOPs, then a SUCCESS {} split across two chunks, then the
    // end-of-message marker.
    let success = [0xB1, crate::message::SUCCESS, 0xA0];
    server.write_all(&[0x00, 0x00]).await.unwrap(); // NOOP
    server.write_all(&[0x00, 0x00]).await.unwrap(); // NOOP
    server.write_all(&[0x00, 0x01, success[0]]).await.unwrap();
    server
        .write_all(&[0x00, 0x02, success[1], success[2]])
        .await
        .unwrap();
    server.write_all(&[0x00, 0x00]).await.unwrap(); // end of message

    match conn.read_message().await.unwrap() {
        Response::Success(meta) => assert!(meta.is_empty()),
        other => panic!("expected SUCCESS, got {other:?}"),
    }
}

#[tokio::test]
async fn read_times_out_on_silent_server() {
    let (client, _server) = tokio::io::duplex(64);
    let mut conn = mem_conn(client);
    conn.set_read_timeout(std::time::Duration::from_millis(50));
    match conn.read_message().await {
        Err(BoltError::Timeout("read")) => {}
        other => panic!("expected read timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn reader_reassembles_multi_chunk_message() {
    let (client, mut server) = tokio::io::duplex(256);
    let mut conn = mem_conn(client);

    // RECORD [Int(1)] one byte per chunk: B1 71 91 01.
    for b in [0xB1, crate::message::RECORD, 0x91, 0x01] {
        server.write_all(&[0x00, 0x01, b]).await.unwrap();
    }
    server.write_all(&[0x00, 0x00]).await.unwrap();

    match conn.read_message().await.unwrap() {
        Response::Record(values) => assert_eq!(values, vec![BoltValue::Int(1)]),
        other => panic!("expected RECORD, got {other:?}"),
    }
}
