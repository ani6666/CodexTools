use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{DomainError, EntityName, ModelId};

pub const NETWORK_POLICY_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointPolicy {
    PublicHttps,
    LoopbackDevelopment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkPolicyError {
    UnsupportedVersion,
    InvalidEndpoint,
    ForbiddenAddress,
    EmptyResolution,
}

impl fmt::Display for NetworkPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "network policy version is unsupported",
            Self::InvalidEndpoint => "endpoint is invalid",
            Self::ForbiddenAddress => "network target is forbidden",
            Self::EmptyResolution => "network target did not resolve",
        })
    }
}

impl std::error::Error for NetworkPolicyError {}

#[derive(Clone, Eq, PartialEq)]
pub struct NormalizedEndpoint {
    normalized: String,
    models_url: String,
    host: String,
    port: u16,
    policy: EndpointPolicy,
    literal_ip: Option<IpAddr>,
}

impl fmt::Debug for NormalizedEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalizedEndpoint")
            .field("value", &"[REDACTED_ENDPOINT]")
            .field("policy", &self.policy)
            .finish()
    }
}

impl NormalizedEndpoint {
    pub fn parse(
        version: u16,
        input: &str,
        policy: EndpointPolicy,
    ) -> Result<Self, NetworkPolicyError> {
        if version != NETWORK_POLICY_VERSION {
            return Err(NetworkPolicyError::UnsupportedVersion);
        }
        if input.is_empty()
            || input.len() > 2_048
            || !input.is_ascii()
            || input
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || input.contains(['\\', '?', '#', '@', '%'])
        {
            return Err(NetworkPolicyError::InvalidEndpoint);
        }

        let (scheme, remainder) = input
            .split_once("://")
            .ok_or(NetworkPolicyError::InvalidEndpoint)?;
        let scheme = scheme.to_ascii_lowercase();
        match policy {
            EndpointPolicy::PublicHttps if scheme != "https" => {
                return Err(NetworkPolicyError::InvalidEndpoint);
            }
            EndpointPolicy::LoopbackDevelopment if !matches!(scheme.as_str(), "http" | "https") => {
                return Err(NetworkPolicyError::InvalidEndpoint);
            }
            _ => {}
        }
        let authority_end = remainder.find('/').unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        let path = &remainder[authority_end..];
        if authority.is_empty() || path.len() > 512 {
            return Err(NetworkPolicyError::InvalidEndpoint);
        }
        let (host, explicit_port, literal_ip) = parse_authority(authority)?;
        let port = explicit_port.unwrap_or(if scheme == "https" { 443 } else { 80 });
        if port == 0 || (policy == EndpointPolicy::PublicHttps && port != 443) {
            return Err(NetworkPolicyError::InvalidEndpoint);
        }
        let normalized_path = normalize_path(path)?;

        match policy {
            EndpointPolicy::PublicHttps => {
                if host == "localhost" || literal_ip.is_some_and(|ip| !is_public_address(ip)) {
                    return Err(NetworkPolicyError::ForbiddenAddress);
                }
            }
            EndpointPolicy::LoopbackDevelopment => {
                if host != "localhost" && !literal_ip.is_some_and(|address| address.is_loopback()) {
                    return Err(NetworkPolicyError::ForbiddenAddress);
                }
            }
        }

        let authority = render_authority(
            &host,
            literal_ip,
            (port != default_port(&scheme)).then_some(port),
        );
        let normalized = format!("{scheme}://{authority}{normalized_path}");
        let models_url = if normalized_path.is_empty() {
            format!("{scheme}://{authority}/models")
        } else {
            format!("{scheme}://{authority}{normalized_path}/models")
        };
        Ok(Self {
            normalized,
            models_url,
            host,
            port,
            policy,
            literal_ip,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    #[must_use]
    pub fn models_url(&self) -> &str {
        &self.models_url
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn policy(&self) -> EndpointPolicy {
        self.policy
    }

    #[must_use]
    pub const fn literal_ip(&self) -> Option<IpAddr> {
        self.literal_ip
    }

    pub fn approve_addresses(&self, addresses: &[IpAddr]) -> Result<(), NetworkPolicyError> {
        if addresses.is_empty() {
            return Err(NetworkPolicyError::EmptyResolution);
        }
        if addresses
            .iter()
            .copied()
            .all(|address| self.address_allowed(address))
        {
            Ok(())
        } else {
            Err(NetworkPolicyError::ForbiddenAddress)
        }
    }

    #[must_use]
    pub fn address_allowed(&self, address: IpAddr) -> bool {
        match self.policy {
            EndpointPolicy::PublicHttps => is_public_address(address),
            EndpointPolicy::LoopbackDevelopment => address.is_loopback(),
        }
    }
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" { 443 } else { 80 }
}

fn render_authority(host: &str, literal_ip: Option<IpAddr>, port: Option<u16>) -> String {
    let rendered_host = if matches!(literal_ip, Some(IpAddr::V6(_))) {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    port.map_or(rendered_host.clone(), |port| {
        format!("{rendered_host}:{port}")
    })
}

fn parse_authority(
    authority: &str,
) -> Result<(String, Option<u16>, Option<IpAddr>), NetworkPolicyError> {
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or(NetworkPolicyError::InvalidEndpoint)?;
        let host = &bracketed[..end];
        let tail = &bracketed[end + 1..];
        let port = if tail.is_empty() {
            None
        } else {
            Some(parse_port(
                tail.strip_prefix(':')
                    .ok_or(NetworkPolicyError::InvalidEndpoint)?,
            )?)
        };
        (host, port)
    } else {
        if authority.matches(':').count() > 1 {
            return Err(NetworkPolicyError::InvalidEndpoint);
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(parse_port(port)?)),
            None => (authority, None),
        }
    };
    if host.is_empty() || host.len() > 253 {
        return Err(NetworkPolicyError::InvalidEndpoint);
    }
    let host = host.to_ascii_lowercase();
    let literal_ip = host.parse::<IpAddr>().ok();
    if literal_ip.is_none()
        && (looks_like_ambiguous_ip(&host)
            || host
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
            || !host.split('.').all(valid_dns_label))
    {
        return Err(NetworkPolicyError::InvalidEndpoint);
    }
    let host = literal_ip.map_or(host, |address| address.to_string());
    Ok((host, port, literal_ip))
}

fn looks_like_ambiguous_ip(host: &str) -> bool {
    host.split('.').any(|label| {
        label.strip_prefix("0x").is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    })
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn parse_port(value: &str) -> Result<u16, NetworkPolicyError> {
    if value.is_empty()
        || value.len() > 5
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(NetworkPolicyError::InvalidEndpoint);
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(NetworkPolicyError::InvalidEndpoint)
}

fn normalize_path(path: &str) -> Result<String, NetworkPolicyError> {
    if path.is_empty() || path == "/" {
        return Ok(String::new());
    }
    if !path.starts_with('/')
        || path.contains("//")
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
    {
        return Err(NetworkPolicyError::InvalidEndpoint);
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(NetworkPolicyError::InvalidEndpoint);
    }
    Ok(trimmed.to_owned())
}

fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !matches!(a, 0 | 10 | 127 | 224..=255)
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 169 && b == 254)
        && !(a == 172 && (16..=31).contains(&b))
        && !(a == 192 && matches!((b, c), (0, _) | (168, _)))
        && !(a == 198 && matches!(b, 18 | 19 | 51) && (b != 51 || c == 100))
        && !(a == 203 && b == 0 && c == 113)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    if address.to_ipv4_mapped().is_some() {
        return false;
    }
    !address.is_unspecified()
        && !address.is_loopback()
        && (segments[0] & 0xfe00) != 0xfc00
        && (segments[0] & 0xffc0) != 0xfe80
        && (segments[0] & 0xff00) != 0xff00
        && (segments[0] & 0xffc0) != 0xfec0
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && !(segments[0] == 0x2001 && segments[1] == 0)
        && segments[0] != 0x2002
        && !(segments[0] == 0x0064 && segments[1] == 0xff9b)
        && !segments[..6].iter().all(|segment| *segment == 0)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiscoveredModel {
    id: ModelId,
    display_name: Option<EntityName>,
}

impl DiscoveredModel {
    pub fn parse(id: &str, display_name: Option<&str>) -> Result<Self, DomainError> {
        let id = ModelId::parse(id)?;
        id.ensure_preset_metadata_safe()?;
        if display_name.is_some_and(|value| {
            value.contains(['/', '\\'])
                || value.starts_with('~')
                || value
                    .split_whitespace()
                    .any(|part| matches!(part, "." | ".."))
        }) {
            return Err(DomainError::InvalidFormat);
        }
        let display_name = display_name.map(EntityName::parse).transpose()?;
        Ok(Self { id, display_name })
    }

    #[must_use]
    pub const fn id(&self) -> &ModelId {
        &self.id
    }

    #[must_use]
    pub const fn display_name(&self) -> Option<&EntityName> {
        self.display_name.as_ref()
    }
}
