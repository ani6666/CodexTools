use codex_adapter as _;
use codex_application::{
    ApprovedHttpTarget, ApprovedHttpTransport, CancellationController, DnsResolver, NetworkLimits,
    NeverCancelled, ProxyMode, RedirectMode, TransportErrorCode,
};
use codex_domain::{EndpointPolicy, NormalizedEndpoint};
use local_infrastructure::{NativeHttpTransport, SystemDnsResolver};
use native_tls as _;
use rusqlite as _;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use windows_platform as _;
use zeroize::Zeroizing;

struct Server {
    port: u16,
    request: mpsc::Receiver<Vec<u8>>,
    join: thread::JoinHandle<()>,
}
fn server(response_parts: Vec<(Duration, Vec<u8>)>) -> Server {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = mpsc::sync_channel(1);
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
        }
        let _ = sender.send(request);
        for (delay, part) in response_parts {
            thread::sleep(delay);
            if stream.write_all(&part).is_err() {
                break;
            }
        }
    });
    Server {
        port,
        request: receiver,
        join,
    }
}
fn target(port: u16, limits: NetworkLimits) -> ApprovedHttpTarget {
    let endpoint = NormalizedEndpoint::parse(
        1,
        &format!("http://localhost:{port}/v1"),
        EndpointPolicy::LoopbackDevelopment,
    )
    .unwrap();
    ApprovedHttpTarget::new(endpoint, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], limits).unwrap()
}

fn tls_target(port: u16) -> ApprovedHttpTarget {
    let endpoint = NormalizedEndpoint::parse(
        1,
        &format!("https://localhost:{port}/v1"),
        EndpointPolicy::LoopbackDevelopment,
    )
    .unwrap();
    ApprovedHttpTarget::new(
        endpoint,
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        NetworkLimits::default(),
    )
    .unwrap()
}

#[test]
fn approved_address_pinning_preserves_host_and_disables_proxy_redirect() {
    let body = b"{\"data\":[{\"id\":\"model-a\"}]}";
    let server = server(vec![
        (
            Duration::ZERO,
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
        ),
        (Duration::ZERO, body.to_vec()),
    ]);
    let target = target(server.port, NetworkLimits::default());
    assert_eq!(target.proxy_mode(), ProxyMode::Disabled);
    assert_eq!(target.redirect_mode(), RedirectMode::Disabled);
    let mut secret_canary =
        Zeroizing::new([b"sk-".as_slice(), b"SYNTHETIC_12345678901234567890"].concat());
    let result = NativeHttpTransport::new()
        .get_models(&target, &mut secret_canary, &NeverCancelled)
        .unwrap();
    assert_eq!(result.status(), 200);
    assert_eq!(result.body(), body);
    assert!(!format!("{result:?}").contains("model-a"));
    let request = server.request.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(
        request
            .windows(b"Host: localhost".len())
            .any(|window| window == b"Host: localhost")
    );
    assert!(
        request
            .windows(secret_canary.len())
            .any(|window| window == secret_canary.as_slice())
    );
    server.join.join().unwrap();
}

#[test]
fn redirect_is_returned_without_following_and_chunked_is_bounded() {
    let redirect=server(vec![(Duration::ZERO,b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest\r\nContent-Length: 0\r\n\r\n".to_vec())]);
    let mut auth = Zeroizing::new(b"SAMPLE".to_vec());
    let response = NativeHttpTransport::new()
        .get_models(
            &target(redirect.port, NetworkLimits::default()),
            &mut auth,
            &NeverCancelled,
        )
        .unwrap();
    assert_eq!(response.status(), 302);
    redirect.join.join().unwrap();
    let chunked=server(vec![(Duration::ZERO,b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"data\"\r\n4\r\n:[]}\r\n0\r\n\r\n".to_vec())]);
    let response = NativeHttpTransport::new()
        .get_models(
            &target(chunked.port, NetworkLimits::default()),
            &mut auth,
            &NeverCancelled,
        )
        .unwrap();
    assert_eq!(response.body(), b"{\"data\":[]}");
    chunked.join.join().unwrap();
}

#[test]
fn oversized_content_length_and_slowloris_timeout_fail_closed() {
    let oversized = server(vec![(
        Duration::ZERO,
        b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n".to_vec(),
    )]);
    let mut auth = Zeroizing::new(b"SAMPLE".to_vec());
    assert!(matches!(
        NativeHttpTransport::new().get_models(
            &target(oversized.port, NetworkLimits::default()),
            &mut auth,
            &NeverCancelled
        ),
        Err(TransportErrorCode::ResponseTooLarge)
    ));
    oversized.join.join().unwrap();
    let slowloris = server(vec![(
        Duration::from_millis(300),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )]);
    let limits = NetworkLimits {
        total_timeout: Duration::from_millis(80),
        ..NetworkLimits::default()
    };
    assert!(matches!(
        NativeHttpTransport::new().get_models(
            &target(slowloris.port, limits),
            &mut auth,
            &NeverCancelled
        ),
        Err(TransportErrorCode::Timeout)
    ));
    slowloris.join.join().unwrap();
}

#[test]
fn malformed_headers_and_early_connection_close_are_safe_codes() {
    let malformed = server(vec![(
        Duration::ZERO,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n".to_vec(),
    )]);
    let mut auth = Zeroizing::new(b"SAMPLE".to_vec());
    assert!(matches!(
        NativeHttpTransport::new().get_models(
            &target(malformed.port, NetworkLimits::default()),
            &mut auth,
            &NeverCancelled,
        ),
        Err(TransportErrorCode::InvalidResponse)
    ));
    malformed.join.join().unwrap();

    let closed = server(Vec::new());
    assert!(matches!(
        NativeHttpTransport::new().get_models(
            &target(closed.port, NetworkLimits::default()),
            &mut auth,
            &NeverCancelled,
        ),
        Err(TransportErrorCode::InvalidResponse | TransportErrorCode::NetworkUnavailable)
    ));
    closed.join.join().unwrap();
}

#[test]
fn cancellation_interrupts_read_and_mixed_allowed_and_denied_dns_fails() {
    let slow = server(vec![(
        Duration::from_millis(500),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )]);
    let cancellation = CancellationController::new();
    let trigger = cancellation.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        let _ = trigger.cancel();
    });
    let mut auth = Zeroizing::new(b"SAMPLE".to_vec());
    assert!(matches!(
        NativeHttpTransport::new().get_models(
            &target(slow.port, NetworkLimits::default()),
            &mut auth,
            &cancellation
        ),
        Err(TransportErrorCode::Cancelled)
    ));
    slow.join.join().unwrap();
    let public =
        NormalizedEndpoint::parse(1, "https://api.example.com/v1", EndpointPolicy::PublicHttps)
            .unwrap();
    assert!(
        ApprovedHttpTarget::new(
            public,
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))
            ],
            NetworkLimits::default()
        )
        .is_err()
    );
}

#[test]
fn system_resolver_is_bounded_and_only_returns_localhost_addresses() {
    let addresses = SystemDnsResolver
        .resolve(
            "localhost",
            443,
            Instant::now() + Duration::from_secs(2),
            &NeverCancelled,
        )
        .unwrap();
    assert!(!addresses.is_empty());
    assert!(addresses.iter().all(IpAddr::is_loopback));
}

#[test]
fn invalid_tls_is_classified_without_an_insecure_certificate_escape_hatch() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let join = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hello = [0_u8; 1_024];
        let _ = stream.read(&mut hello);
        let _ = stream.write_all(b"not-a-tls-record");
    });
    let mut auth = Zeroizing::new(b"SAMPLE".to_vec());
    assert!(matches!(
        NativeHttpTransport::new().get_models(&tls_target(port), &mut auth, &NeverCancelled),
        Err(TransportErrorCode::TlsFailure)
    ));
    join.join().unwrap();
}

#[test]
fn parallel_requests_remain_isolated() {
    let servers = (0..8)
        .map(|index| {
            let body = format!("{{\"data\":[{{\"id\":\"model-{index}\"}}]}}").into_bytes();
            server(vec![
                (
                    Duration::ZERO,
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                        .into_bytes(),
                ),
                (Duration::ZERO, body),
            ])
        })
        .collect::<Vec<_>>();
    let clients = servers
        .iter()
        .map(|server| server.port)
        .map(|port| {
            thread::spawn(move || {
                let mut auth = Zeroizing::new(b"SAMPLE".to_vec());
                NativeHttpTransport::new()
                    .get_models(
                        &target(port, NetworkLimits::default()),
                        &mut auth,
                        &NeverCancelled,
                    )
                    .unwrap()
                    .body()
                    .to_vec()
            })
        })
        .collect::<Vec<_>>();
    let bodies = clients
        .into_iter()
        .map(|client| client.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(bodies.len(), 8);
    for server in servers {
        server.join.join().unwrap();
    }
}
