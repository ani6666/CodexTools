use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use codex_domain::{EndpointPolicy, NormalizedEndpoint};

#[test]
fn public_https_is_canonical_and_rejects_ambiguous_urls() {
    let endpoint =
        NormalizedEndpoint::parse(1, "https://api.example.com/v1", EndpointPolicy::PublicHttps)
            .unwrap();
    assert_eq!(endpoint.as_str(), "https://api.example.com/v1");
    assert_eq!(endpoint.models_url(), "https://api.example.com/v1/models");
    assert_eq!(endpoint.host(), "api.example.com");
    assert_eq!(endpoint.port(), 443);
    assert_eq!(
        NormalizedEndpoint::parse(
            1,
            "https://api.example.com:443/v1",
            EndpointPolicy::PublicHttps
        )
        .unwrap()
        .as_str(),
        "https://api.example.com/v1"
    );
    assert_eq!(
        NormalizedEndpoint::parse(
            1,
            "HTTPS://API.Example.COM/v1/",
            EndpointPolicy::PublicHttps,
        )
        .unwrap()
        .as_str(),
        "https://api.example.com/v1"
    );

    for value in [
        "http://api.example.com/v1",
        "https://user@api.example.com/v1",
        "https://api.example.com/v1?token=SAMPLE",
        "https://api.example.com/v1#fragment",
        "https://api.example.com\\v1",
        "https://例子.example/v1",
        "https://api.example.com:444/v1",
        "https://127.1/v1",
        "https://0x7f.0.0.1/v1",
        "file:///v1",
    ] {
        assert!(
            NormalizedEndpoint::parse(1, value, EndpointPolicy::PublicHttps).is_err(),
            "{value}"
        );
    }
}

#[test]
fn loopback_mode_is_explicit_and_private_lan_is_never_loopback() {
    for value in [
        "http://localhost:43123/v1",
        "http://127.0.0.2:43123/v1",
        "http://[::1]:43123/v1",
    ] {
        assert!(
            NormalizedEndpoint::parse(1, value, EndpointPolicy::LoopbackDevelopment).is_ok(),
            "{value}"
        );
    }
    for value in [
        "http://192.168.1.2:43123/v1",
        "http://10.0.0.1:43123/v1",
        "http://100.64.0.1:43123/v1",
        "http://169.254.169.254:80/v1",
    ] {
        assert!(
            NormalizedEndpoint::parse(1, value, EndpointPolicy::LoopbackDevelopment).is_err(),
            "{value}"
        );
    }
}

#[test]
fn resolved_address_policy_fails_closed_for_every_forbidden_class() {
    let public =
        NormalizedEndpoint::parse(1, "https://api.example.com/v1", EndpointPolicy::PublicHttps)
            .unwrap();
    assert!(
        public
            .approve_addresses(&[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
            .is_ok()
    );
    for address in [
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6("fc00::1".parse().unwrap()),
        IpAddr::V6("fe80::1".parse().unwrap()),
        IpAddr::V6("ff02::1".parse().unwrap()),
        IpAddr::V6("::ffff:169.254.169.254".parse().unwrap()),
        IpAddr::V6("::ffff:93.184.216.34".parse().unwrap()),
        IpAddr::V6("64:ff9b::5db8:d822".parse().unwrap()),
    ] {
        assert!(
            public
                .approve_addresses(&[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), address])
                .is_err(),
            "{address}"
        );
    }
}
