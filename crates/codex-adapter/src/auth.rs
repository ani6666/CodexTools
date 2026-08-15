use codex_application::{
    AuthorizationConsumer, AuthorizationParseError, CredentialAuthorizationParser,
};
use codex_domain::{CredentialKind, SchemaFingerprint};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Default)]
pub struct CodexAuthorizationParser;

impl CodexAuthorizationParser {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CredentialAuthorizationParser for CodexAuthorizationParser {
    fn parse(
        &self,
        kind: CredentialKind,
        expected_schema: &SchemaFingerprint,
        document: &[u8],
        consumer: &mut dyn AuthorizationConsumer,
    ) -> Result<(), AuthorizationParseError> {
        let (mode, span) = crate::json::authorization_span(document)
            .map_err(|_| AuthorizationParseError::Invalid)?;
        let expected_mode = match kind {
            CredentialKind::ApiKey => "api_key",
            CredentialKind::OAuthBundle => "oauth",
        };
        if mode != expected_mode {
            return Err(AuthorizationParseError::Invalid);
        }
        let schema = match kind {
            CredentialKind::ApiKey => "OPENAI_API_KEY:string",
            CredentialKind::OAuthBundle => {
                "tokens:{id_token,access_token,refresh_token,account_id}:string"
            }
        };
        if crate::hash::sha256_hex(schema.as_bytes()) != expected_schema.as_str() {
            return Err(AuthorizationParseError::Invalid);
        }
        if kind == CredentialKind::OAuthBundle {
            // 现有 bundle 没有可验证的 expiry；M2.8 不猜测 token 新鲜度。
            return Err(AuthorizationParseError::Unsupported);
        }
        let raw = document
            .get(span.0..span.1)
            .ok_or(AuthorizationParseError::Invalid)?;
        if raw.contains(&b'\\') {
            let decoded = decode_json_string(raw)?;
            consumer.consume(&decoded)
        } else {
            consumer.consume(raw)
        }
    }
}

fn decode_json_string(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthorizationParseError> {
    let mut output = Zeroizing::new(Vec::with_capacity(raw.len()));
    let mut position = 0;
    while position < raw.len() {
        let byte = raw[position];
        position += 1;
        if byte != b'\\' {
            if byte <= 31 {
                return Err(AuthorizationParseError::Invalid);
            }
            output.push(byte);
            continue;
        }
        let escaped = *raw.get(position).ok_or(AuthorizationParseError::Invalid)?;
        position += 1;
        match escaped {
            b'"' | b'\\' | b'/' => output.push(escaped),
            b'b' => output.push(8),
            b'f' => output.push(12),
            b'n' => output.push(b'\n'),
            b'r' => output.push(b'\r'),
            b't' => output.push(b'\t'),
            b'u' => {
                let (scalar, consumed) = decode_unicode(&raw[position..])?;
                position += consumed;
                let mut buffer = [0_u8; 4];
                output.extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
            }
            _ => return Err(AuthorizationParseError::Invalid),
        }
    }
    if output.is_empty() {
        Err(AuthorizationParseError::AuthRequired)
    } else {
        Ok(output)
    }
}

fn decode_unicode(bytes: &[u8]) -> Result<(char, usize), AuthorizationParseError> {
    let first = hex_quad(bytes)?;
    if (0xd800..=0xdbff).contains(&first) {
        if bytes.get(4..6) != Some(b"\\u") {
            return Err(AuthorizationParseError::Invalid);
        }
        let second = hex_quad(&bytes[6..])?;
        if !(0xdc00..=0xdfff).contains(&second) {
            return Err(AuthorizationParseError::Invalid);
        }
        let scalar = 0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00);
        char::from_u32(scalar)
            .map(|value| (value, 10))
            .ok_or(AuthorizationParseError::Invalid)
    } else if (0xdc00..=0xdfff).contains(&first) {
        Err(AuthorizationParseError::Invalid)
    } else {
        char::from_u32(u32::from(first))
            .map(|value| (value, 4))
            .ok_or(AuthorizationParseError::Invalid)
    }
}

fn hex_quad(bytes: &[u8]) -> Result<u16, AuthorizationParseError> {
    let bytes = bytes.get(..4).ok_or(AuthorizationParseError::Invalid)?;
    let mut value = 0_u16;
    for byte in bytes {
        value = value
            .checked_mul(16)
            .and_then(|current| {
                byte.to_ascii_lowercase()
                    .checked_sub(b'0')
                    .and_then(|offset| match offset {
                        0..=9 => Some(current + u16::from(offset)),
                        49..=54 => Some(current + u16::from(offset - 39)),
                        _ => None,
                    })
            })
            .ok_or(AuthorizationParseError::Invalid)?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::CodexAuthorizationParser;
    use codex_application::{
        AuthorizationConsumer, AuthorizationParseError, CredentialAuthorizationParser,
    };
    use codex_domain::{CredentialKind, SchemaFingerprint};

    struct BorrowedCapture {
        expected: Vec<u8>,
        matched: bool,
    }
    impl AuthorizationConsumer for BorrowedCapture {
        fn consume(&mut self, authorization: &[u8]) -> Result<(), AuthorizationParseError> {
            self.matched = authorization == self.expected;
            Ok(())
        }
    }
    fn schema(value: &str) -> SchemaFingerprint {
        SchemaFingerprint::parse(&crate::hash::sha256_hex(value.as_bytes())).unwrap()
    }

    #[test]
    fn api_key_is_borrowed_from_strict_document_and_schema_checked() {
        let parser = CodexAuthorizationParser::new();
        let canary = ["sk-", "SYNTHETIC_12345678901234567890"].concat();
        let document = format!(r#"{{"OPENAI_API_KEY":"{canary}"}}"#);
        let mut capture = BorrowedCapture {
            expected: canary.into_bytes(),
            matched: false,
        };
        parser
            .parse(
                CredentialKind::ApiKey,
                &schema("OPENAI_API_KEY:string"),
                document.as_bytes(),
                &mut capture,
            )
            .unwrap();
        assert!(capture.matched);
        assert_eq!(
            parser.parse(
                CredentialKind::ApiKey,
                &schema("wrong"),
                br#"{"OPENAI_API_KEY":"SAMPLE"}"#,
                &mut capture
            ),
            Err(AuthorizationParseError::Invalid)
        );
    }

    #[test]
    fn oauth_without_expiry_evidence_fails_closed_before_consumption() {
        let parser = CodexAuthorizationParser::new();
        let mut capture = BorrowedCapture {
            expected: Vec::new(),
            matched: false,
        };
        let result = parser.parse(CredentialKind::OAuthBundle, &schema("tokens:{id_token,access_token,refresh_token,account_id}:string"), br#"{"tokens":{"id_token":"ID","access_token":"ACCESS","refresh_token":"REFRESH","account_id":"ACCOUNT"}}"#, &mut capture);
        assert_eq!(result, Err(AuthorizationParseError::Unsupported));
        assert!(!capture.matched);
    }
}
