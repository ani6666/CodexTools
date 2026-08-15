use codex_application::{
    AuthorizationConsumer, AuthorizationParseError, CredentialAuthorizationParser,
};
use codex_domain::{CredentialKind, SchemaFingerprint};
use zeroize::Zeroize;

const AUTH_DOCUMENT_MAXIMUM_BYTES: usize = 1_048_576;
const AUTH_JSON_MAXIMUM_DEPTH: usize = 32;

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
        if document.len() > AUTH_DOCUMENT_MAXIMUM_BYTES {
            return Err(AuthorizationParseError::Invalid);
        }
        let (mode, span) = crate::json::authorization_span(document, AUTH_JSON_MAXIMUM_DEPTH)
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

struct DecodedAuthorization {
    bytes: Vec<u8>,
    #[cfg(test)]
    observer: Option<std::rc::Rc<std::cell::Cell<bool>>>,
}

impl DecodedAuthorization {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            #[cfg(test)]
            observer: None,
        }
    }

    #[cfg(test)]
    fn observed(capacity: usize, observer: std::rc::Rc<std::cell::Cell<bool>>) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            observer: Some(observer),
        }
    }
}

impl std::ops::Deref for DecodedAuthorization {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Drop for DecodedAuthorization {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer.set(self.bytes.iter().all(|byte| *byte == 0));
        }
    }
}

fn decode_json_string(raw: &[u8]) -> Result<DecodedAuthorization, AuthorizationParseError> {
    decode_json_string_into(raw, DecodedAuthorization::new(raw.len()))
}

#[cfg(test)]
fn decode_json_string_observed(
    raw: &[u8],
    observer: std::rc::Rc<std::cell::Cell<bool>>,
) -> Result<DecodedAuthorization, AuthorizationParseError> {
    decode_json_string_into(raw, DecodedAuthorization::observed(raw.len(), observer))
}

fn decode_json_string_into(
    raw: &[u8],
    mut output: DecodedAuthorization,
) -> Result<DecodedAuthorization, AuthorizationParseError> {
    let mut position = 0;
    while position < raw.len() {
        let byte = raw[position];
        position += 1;
        if byte != b'\\' {
            if byte <= 31 {
                return Err(AuthorizationParseError::Invalid);
            }
            output.bytes.push(byte);
            continue;
        }
        let escaped = *raw.get(position).ok_or(AuthorizationParseError::Invalid)?;
        position += 1;
        match escaped {
            b'"' | b'\\' | b'/' => output.bytes.push(escaped),
            b'b' => output.bytes.push(8),
            b'f' => output.bytes.push(12),
            b'n' => output.bytes.push(b'\n'),
            b'r' => output.bytes.push(b'\r'),
            b't' => output.bytes.push(b'\t'),
            b'u' => {
                let (scalar, consumed) = decode_unicode(&raw[position..])?;
                position += consumed;
                let mut buffer = [0_u8; 4];
                output
                    .bytes
                    .extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
            }
            _ => return Err(AuthorizationParseError::Invalid),
        }
    }
    if output.bytes.is_empty() {
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
    use super::{CodexAuthorizationParser, decode_json_string_observed};
    use codex_application::{
        AuthorizationConsumer, AuthorizationParseError, CredentialAuthorizationParser,
    };
    use codex_domain::{CredentialKind, SchemaFingerprint};
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
        rc::Rc,
    };

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

    fn nested_unknown_array(depth: usize) -> String {
        format!(
            r#"{{"unknown":{}null{},"OPENAI_API_KEY":"SAMPLE"}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        )
    }

    #[test]
    fn credential_json_depth_budget_accepts_near_limit_and_rejects_over_limit() {
        const AUTH_DEPTH_LIMIT: usize = 32;
        let parser = CodexAuthorizationParser::new();
        let mut capture = BorrowedCapture {
            expected: b"SAMPLE".to_vec(),
            matched: false,
        };
        parser
            .parse(
                CredentialKind::ApiKey,
                &schema("OPENAI_API_KEY:string"),
                nested_unknown_array(AUTH_DEPTH_LIMIT - 1).as_bytes(),
                &mut capture,
            )
            .unwrap();
        assert!(capture.matched);
        assert_eq!(
            parser.parse(
                CredentialKind::ApiKey,
                &schema("OPENAI_API_KEY:string"),
                nested_unknown_array(AUTH_DEPTH_LIMIT).as_bytes(),
                &mut capture,
            ),
            Err(AuthorizationParseError::Invalid)
        );
    }

    #[test]
    fn general_scan_parser_keeps_a_separate_compatibility_depth_budget() {
        const COMPATIBILITY_DEPTH_LIMIT: usize = 128;
        assert!(
            crate::json::classify(nested_unknown_array(COMPATIBILITY_DEPTH_LIMIT - 1).as_bytes())
                .is_ok()
        );
        assert!(
            crate::json::classify(nested_unknown_array(COMPATIBILITY_DEPTH_LIMIT).as_bytes())
                .is_err()
        );
    }

    #[test]
    fn credential_document_is_bounded_to_one_mibibyte() {
        const AUTH_DOCUMENT_LIMIT: usize = 1_048_576;
        let parser = CodexAuthorizationParser::new();
        let mut document = br#"{"padding":"","OPENAI_API_KEY":"SAMPLE"}"#.to_vec();
        let insertion = document.iter().position(|byte| *byte == b'"').unwrap() + 11;
        document.splice(
            insertion..insertion,
            std::iter::repeat_n(b'A', AUTH_DOCUMENT_LIMIT - document.len()),
        );
        assert_eq!(document.len(), AUTH_DOCUMENT_LIMIT);
        let mut capture = BorrowedCapture {
            expected: b"SAMPLE".to_vec(),
            matched: false,
        };
        parser
            .parse(
                CredentialKind::ApiKey,
                &schema("OPENAI_API_KEY:string"),
                &document,
                &mut capture,
            )
            .unwrap();
        document.push(b' ');
        assert_eq!(
            parser.parse(
                CredentialKind::ApiKey,
                &schema("OPENAI_API_KEY:string"),
                &document,
                &mut capture
            ),
            Err(AuthorizationParseError::Invalid)
        );
    }

    struct PanickingConsumer;
    impl AuthorizationConsumer for PanickingConsumer {
        fn consume(&mut self, _: &[u8]) -> Result<(), AuthorizationParseError> {
            panic!("synthetic authorization consumer panic")
        }
    }

    #[test]
    fn escaped_authorization_buffer_zeroizes_when_consumer_panics() {
        let observed = Rc::new(Cell::new(false));
        let observer = observed.clone();
        let raw = [b"sk-".as_slice(), b"SYNTHETIC_12345678901234567890\\u0031"].concat();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let decoded = decode_json_string_observed(&raw, observer).unwrap();
            PanickingConsumer.consume(&decoded).unwrap();
        }));
        assert!(result.is_err());
        assert!(observed.get());
    }
}
