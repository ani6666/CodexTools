use std::{
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use codex_application::{
    ApprovedHttpTarget, ApprovedHttpTransport, CancellationProbe, DnsResolver, ProxyMode,
    RedirectMode, ResolverErrorCode, TransportErrorCode, TransportResponse,
};
use native_tls::{HandshakeError, MidHandshakeTlsStream, TlsConnector, TlsStream};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
        cancellation: &dyn CancellationProbe,
    ) -> Result<Vec<IpAddr>, ResolverErrorCode> {
        if cancellation.is_cancelled() {
            return Err(ResolverErrorCode::Cancelled);
        }
        let owned_host = host.to_owned();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = (owned_host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.map(|address| address.ip()).collect::<Vec<_>>());
            let _ = sender.send(result);
        });
        loop {
            if cancellation.is_cancelled() {
                return Err(ResolverErrorCode::Cancelled);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(ResolverErrorCode::Timeout)?;
            let wait = remaining.min(Duration::from_millis(50));
            match receiver.recv_timeout(wait) {
                Ok(Ok(mut addresses)) => {
                    addresses.sort_unstable();
                    addresses.dedup();
                    return Ok(addresses);
                }
                Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ResolverErrorCode::NetworkUnavailable);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeHttpTransport;

impl NativeHttpTransport {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn connect_addr(
        address: SocketAddr,
        timeout: Duration,
        deadline: Instant,
        cancellation: &dyn CancellationProbe,
    ) -> Result<TcpStream, TransportErrorCode> {
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = sender.send(TcpStream::connect_timeout(&address, timeout));
        });
        loop {
            if cancellation.is_cancelled() {
                return Err(TransportErrorCode::Cancelled);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(TransportErrorCode::Timeout)?;
            match receiver.recv_timeout(remaining.min(Duration::from_millis(25))) {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) => return Err(map_io(&error)),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(TransportErrorCode::NetworkUnavailable);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

impl ApprovedHttpTransport for NativeHttpTransport {
    fn get_models(
        &mut self,
        target: &ApprovedHttpTarget,
        authorization: &mut [u8],
        cancellation: &dyn CancellationProbe,
    ) -> Result<TransportResponse, TransportErrorCode> {
        debug_assert_eq!(target.redirect_mode(), RedirectMode::Disabled);
        debug_assert_eq!(target.proxy_mode(), ProxyMode::Disabled);
        if cancellation.is_cancelled() {
            return Err(TransportErrorCode::Cancelled);
        }
        let deadline = Instant::now()
            .checked_add(target.limits().total_timeout)
            .ok_or(TransportErrorCode::Internal)?;
        let mut last_error = TransportErrorCode::NetworkUnavailable;
        for address in target.connect_addresses().iter().copied() {
            if cancellation.is_cancelled() {
                return Err(TransportErrorCode::Cancelled);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(TransportErrorCode::Timeout)?;
            let timeout = remaining.min(target.limits().connect_timeout);
            match Self::connect_addr(address, timeout, deadline, cancellation) {
                Ok(stream) => {
                    stream
                        .set_nonblocking(true)
                        .map_err(|error| map_io(&error))?;
                    let mut stream = if target.endpoint().as_str().starts_with("https://") {
                        HttpStream::Tls(Box::new(handshake_tls(
                            stream,
                            target.endpoint().host(),
                            deadline,
                            cancellation,
                        )?))
                    } else {
                        HttpStream::Plain(stream)
                    };
                    return exchange(&mut stream, target, authorization, deadline, cancellation);
                }
                Err(TransportErrorCode::Cancelled) => return Err(TransportErrorCode::Cancelled),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
}

enum HttpStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}
impl Read for HttpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}
impl Write for HttpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn handshake_tls(
    stream: TcpStream,
    host: &str,
    deadline: Instant,
    cancellation: &dyn CancellationProbe,
) -> Result<TlsStream<TcpStream>, TransportErrorCode> {
    let connector = TlsConnector::builder()
        .build()
        .map_err(|_| TransportErrorCode::TlsFailure)?;
    match connector.connect(host, stream) {
        Ok(stream) => Ok(stream),
        Err(HandshakeError::Failure(_)) => Err(TransportErrorCode::TlsFailure),
        Err(HandshakeError::WouldBlock(mid)) => continue_handshake(mid, deadline, cancellation),
    }
}

fn continue_handshake(
    mut mid: MidHandshakeTlsStream<TcpStream>,
    deadline: Instant,
    cancellation: &dyn CancellationProbe,
) -> Result<TlsStream<TcpStream>, TransportErrorCode> {
    loop {
        wait_ready(deadline, cancellation)?;
        match mid.handshake() {
            Ok(stream) => return Ok(stream),
            Err(HandshakeError::WouldBlock(next)) => mid = next,
            Err(HandshakeError::Failure(_)) => return Err(TransportErrorCode::TlsFailure),
        }
    }
}

fn exchange(
    stream: &mut HttpStream,
    target: &ApprovedHttpTarget,
    authorization: &mut [u8],
    deadline: Instant,
    cancellation: &dyn CancellationProbe,
) -> Result<TransportResponse, TransportErrorCode> {
    let endpoint = target.endpoint();
    let path = endpoint
        .models_url()
        .splitn(4, '/')
        .nth(3)
        .map_or_else(|| "/models".to_owned(), |path| format!("/{path}"));
    let host = if endpoint.host().contains(':') {
        format!("[{}]", endpoint.host())
    } else {
        endpoint.host().to_owned()
    };
    let host = if (endpoint.as_str().starts_with("https://") && endpoint.port() == 443)
        || (endpoint.as_str().starts_with("http://") && endpoint.port() == 80)
    {
        host
    } else {
        format!("{host}:{}", endpoint.port())
    };
    let mut request = Zeroizing::new(Vec::with_capacity(authorization.len() + 256));
    request.extend_from_slice(b"GET ");
    request.extend_from_slice(path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(b"\r\nAuthorization: Bearer ");
    request.extend_from_slice(authorization);
    request.extend_from_slice(
        b"\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
    );
    write_cancellable(stream, &request, deadline, cancellation)?;
    request.zeroize();
    read_response(stream, target, deadline, cancellation)
}

fn write_cancellable(
    stream: &mut impl Write,
    bytes: &[u8],
    deadline: Instant,
    cancellation: &dyn CancellationProbe,
) -> Result<(), TransportErrorCode> {
    let mut position = 0;
    while position < bytes.len() {
        if cancellation.is_cancelled() {
            return Err(TransportErrorCode::Cancelled);
        }
        match stream.write(&bytes[position..]) {
            Ok(0) => return Err(TransportErrorCode::NetworkUnavailable),
            Ok(count) => position += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                wait_ready(deadline, cancellation)?
            }
            Err(error) => return Err(map_io(&error)),
        }
    }
    Ok(())
}

fn read_response(
    stream: &mut impl Read,
    target: &ApprovedHttpTarget,
    deadline: Instant,
    cancellation: &dyn CancellationProbe,
) -> Result<TransportResponse, TransportErrorCode> {
    let limits = target.limits();
    let mut received = Zeroizing::new(Vec::new());
    let header_end = loop {
        if let Some(position) = find_bytes(&received, b"\r\n\r\n") {
            break position + 4;
        }
        if received.len() >= limits.maximum_header_bytes {
            return Err(TransportErrorCode::ResponseTooLarge);
        }
        read_more(
            stream,
            &mut received,
            limits.maximum_header_bytes,
            deadline,
            cancellation,
        )?;
    };
    let (status, content_length, chunked) = parse_headers(&received[..header_end])?;
    if content_length.is_some_and(|length| length > limits.maximum_response_bytes) {
        return Err(TransportErrorCode::ResponseTooLarge);
    }
    let mut encoded = Zeroizing::new(received[header_end..].to_vec());
    received.zeroize();
    let body = if chunked {
        loop {
            match decode_chunked(&encoded, limits.maximum_response_bytes)? {
                Some(body) => break body,
                None => read_more(
                    stream,
                    &mut encoded,
                    limits.maximum_response_bytes + 65_536,
                    deadline,
                    cancellation,
                )?,
            }
        }
    } else if let Some(length) = content_length {
        while encoded.len() < length {
            read_more(
                stream,
                &mut encoded,
                limits.maximum_response_bytes,
                deadline,
                cancellation,
            )?;
        }
        if encoded.len() != length {
            return Err(TransportErrorCode::InvalidResponse);
        }
        std::mem::take(&mut *encoded)
    } else {
        while let ReadProgress::Data = read_once(
            stream,
            &mut encoded,
            limits.maximum_response_bytes,
            deadline,
            cancellation,
        )? {}
        std::mem::take(&mut *encoded)
    };
    Ok(TransportResponse::new(status, body))
}

fn parse_headers(header: &[u8]) -> Result<(u16, Option<usize>, bool), TransportErrorCode> {
    if !header.is_ascii() {
        return Err(TransportErrorCode::InvalidResponse);
    }
    let mut lines = header
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let status_line = lines.next().ok_or(TransportErrorCode::InvalidResponse)?;
    let mut parts = status_line.split(|byte| *byte == b' ');
    if parts.next() != Some(b"HTTP/1.1".as_slice()) {
        return Err(TransportErrorCode::InvalidResponse);
    }
    let status = std::str::from_utf8(parts.next().ok_or(TransportErrorCode::InvalidResponse)?)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or(TransportErrorCode::InvalidResponse)?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line[0].is_ascii_whitespace() {
            return Err(TransportErrorCode::InvalidResponse);
        }
        let separator = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(TransportErrorCode::InvalidResponse)?;
        let (name, value) = (&line[..separator], &line[separator + 1..]);
        let value = trim_ascii(value);
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(TransportErrorCode::InvalidResponse);
            }
            content_length = Some(
                std::str::from_utf8(value)
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or(TransportErrorCode::InvalidResponse)?,
            );
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case(b"chunked") {
                return Err(TransportErrorCode::InvalidResponse);
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case(b"content-encoding")
            && !value.eq_ignore_ascii_case(b"identity")
        {
            return Err(TransportErrorCode::InvalidResponse);
        }
    }
    if chunked && content_length.is_some() {
        return Err(TransportErrorCode::InvalidResponse);
    }
    Ok((status, content_length, chunked))
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn decode_chunked(encoded: &[u8], maximum: usize) -> Result<Option<Vec<u8>>, TransportErrorCode> {
    let mut position = 0;
    let mut output = Vec::new();
    loop {
        let Some(line_end) = find_bytes(&encoded[position..], b"\r\n") else {
            return Ok(None);
        };
        let line = &encoded[position..position + line_end];
        if line.is_empty()
            || line.len() > 16
            || line.contains(&b';')
            || !line.iter().all(u8::is_ascii_hexdigit)
        {
            return Err(TransportErrorCode::InvalidResponse);
        }
        let size = usize::from_str_radix(
            std::str::from_utf8(line).map_err(|_| TransportErrorCode::InvalidResponse)?,
            16,
        )
        .map_err(|_| TransportErrorCode::InvalidResponse)?;
        position += line_end + 2;
        if size == 0 {
            return if encoded.get(position..position + 2) == Some(b"\r\n") {
                Ok(Some(output))
            } else if encoded.len() < position + 2 {
                Ok(None)
            } else {
                Err(TransportErrorCode::InvalidResponse)
            };
        }
        if output
            .len()
            .checked_add(size)
            .is_none_or(|length| length > maximum)
        {
            return Err(TransportErrorCode::ResponseTooLarge);
        }
        let end = position
            .checked_add(size)
            .ok_or(TransportErrorCode::ResponseTooLarge)?;
        if encoded.len() < end + 2 {
            return Ok(None);
        }
        if encoded.get(end..end + 2) != Some(b"\r\n") {
            return Err(TransportErrorCode::InvalidResponse);
        }
        output.extend_from_slice(&encoded[position..end]);
        position = end + 2;
    }
}

enum ReadProgress {
    Data,
    Eof,
}
fn read_more(
    stream: &mut impl Read,
    output: &mut Vec<u8>,
    maximum: usize,
    deadline: Instant,
    cancellation: &dyn CancellationProbe,
) -> Result<(), TransportErrorCode> {
    match read_once(stream, output, maximum, deadline, cancellation)? {
        ReadProgress::Data => Ok(()),
        ReadProgress::Eof => Err(TransportErrorCode::InvalidResponse),
    }
}
fn read_once(
    stream: &mut impl Read,
    output: &mut Vec<u8>,
    maximum: usize,
    deadline: Instant,
    cancellation: &dyn CancellationProbe,
) -> Result<ReadProgress, TransportErrorCode> {
    loop {
        if cancellation.is_cancelled() {
            return Err(TransportErrorCode::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(TransportErrorCode::Timeout);
        }
        let mut buffer = [0_u8; 8_192];
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(ReadProgress::Eof),
            Ok(count) => {
                if output
                    .len()
                    .checked_add(count)
                    .is_none_or(|length| length > maximum)
                {
                    return Err(TransportErrorCode::ResponseTooLarge);
                }
                output.extend_from_slice(&buffer[..count]);
                return Ok(ReadProgress::Data);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                wait_ready(deadline, cancellation)?
            }
            Err(error) => return Err(map_io(&error)),
        }
    }
}

fn wait_ready(
    deadline: Instant,
    cancellation: &dyn CancellationProbe,
) -> Result<(), TransportErrorCode> {
    if cancellation.is_cancelled() {
        return Err(TransportErrorCode::Cancelled);
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(TransportErrorCode::Timeout)?;
    thread::sleep(remaining.min(Duration::from_millis(5)));
    Ok(())
}
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
fn map_io(error: &io::Error) -> TransportErrorCode {
    match error.kind() {
        io::ErrorKind::TimedOut => TransportErrorCode::Timeout,
        io::ErrorKind::InvalidData => TransportErrorCode::InvalidResponse,
        _ => TransportErrorCode::NetworkUnavailable,
    }
}
