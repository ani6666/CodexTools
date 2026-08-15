use codex_application::CompatibilityReason;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JsonKey {
    field: JsonField,
    fingerprint: u64,
    scalar_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsonField {
    ApiKey,
    Tokens,
    IdToken,
    AccessToken,
    RefreshToken,
    AccountId,
    Other,
}

#[derive(Clone, Copy, Debug, Default)]
struct ObjectShape {
    api_key: Option<(usize, usize)>,
    tokens: bool,
    id_token: bool,
    access_token: Option<(usize, usize)>,
    refresh_token: bool,
    account_id: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Context {
    Root,
    Tokens,
    Other,
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn parse(mut self) -> Result<ObjectShape, CompatibilityReason> {
        self.ws();
        let shape = self.object(Context::Root)?;
        self.ws();
        if self.position != self.bytes.len() {
            return Err(CompatibilityReason::UnknownAuthenticationShape);
        }
        Ok(shape)
    }

    fn ws(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.position += 1;
        }
    }

    fn object(&mut self, context: Context) -> Result<ObjectShape, CompatibilityReason> {
        if self.bytes.get(self.position) != Some(&b'{') {
            return Err(CompatibilityReason::UnknownAuthenticationShape);
        }
        self.position += 1;
        self.ws();
        let mut seen = Vec::<JsonKey>::new();
        let mut shape = ObjectShape::default();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(shape);
        }
        loop {
            let key = self.key()?;
            if seen.contains(&key) {
                return Err(CompatibilityReason::UnknownAuthenticationShape);
            }
            seen.push(key);
            self.ws();
            if self.bytes.get(self.position) != Some(&b':') {
                return Err(CompatibilityReason::UnknownAuthenticationShape);
            }
            self.position += 1;
            self.ws();
            match (context, key.field) {
                (Context::Root, JsonField::ApiKey) => {
                    shape.api_key = Some(self.nonempty_string_span()?)
                }
                (Context::Root, JsonField::Tokens) => {
                    let tokens = self.object(Context::Tokens)?;
                    shape.tokens = true;
                    shape.id_token = tokens.id_token;
                    shape.access_token = tokens.access_token;
                    shape.refresh_token = tokens.refresh_token;
                    shape.account_id = tokens.account_id;
                }
                (Context::Tokens, JsonField::IdToken) => shape.id_token = self.nonempty_string()?,
                (Context::Tokens, JsonField::AccessToken) => {
                    shape.access_token = Some(self.nonempty_string_span()?)
                }
                (Context::Tokens, JsonField::RefreshToken) => {
                    shape.refresh_token = self.nonempty_string()?;
                }
                (Context::Tokens, JsonField::AccountId) => {
                    shape.account_id = self.nonempty_string()?
                }
                _ => self.value(Context::Other)?,
            }
            self.ws();
            match self.bytes.get(self.position) {
                Some(b',') => {
                    self.position += 1;
                    self.ws();
                }
                Some(b'}') => {
                    self.position += 1;
                    return Ok(shape);
                }
                _ => return Err(CompatibilityReason::UnknownAuthenticationShape),
            }
        }
    }

    fn value(&mut self, context: Context) -> Result<(), CompatibilityReason> {
        self.ws();
        match self.bytes.get(self.position) {
            Some(b'{') => self.object(context).map(|_| ()),
            Some(b'[') => self.array(),
            Some(b'"') => self.skip_string(),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(CompatibilityReason::UnknownAuthenticationShape),
        }
    }

    fn array(&mut self) -> Result<(), CompatibilityReason> {
        self.position += 1;
        self.ws();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(());
        }
        loop {
            self.value(Context::Other)?;
            self.ws();
            match self.bytes.get(self.position) {
                Some(b',') => {
                    self.position += 1;
                    self.ws();
                }
                Some(b']') => {
                    self.position += 1;
                    return Ok(());
                }
                _ => return Err(CompatibilityReason::UnknownAuthenticationShape),
            }
        }
    }

    fn key(&mut self) -> Result<JsonKey, CompatibilityReason> {
        const MAX_KEY_SCALARS: usize = 256;
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x100_0000_01b3;
        if self.bytes.get(self.position) != Some(&b'"') {
            return Err(CompatibilityReason::UnknownAuthenticationShape);
        }
        self.position += 1;
        let mut fingerprint = OFFSET;
        let mut scalar_count = 0_usize;
        let mut candidates = [
            (JsonField::ApiKey, "OPENAI_API_KEY".chars()),
            (JsonField::Tokens, "tokens".chars()),
            (JsonField::IdToken, "id_token".chars()),
            (JsonField::AccessToken, "access_token".chars()),
            (JsonField::RefreshToken, "refresh_token".chars()),
            (JsonField::AccountId, "account_id".chars()),
        ]
        .map(|(field, expected)| (field, expected, true));
        loop {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
            if byte == b'"' {
                self.position += 1;
                let field = candidates
                    .into_iter()
                    .find_map(|(field, mut expected, matches)| {
                        (matches && expected.next().is_none()).then_some(field)
                    })
                    .unwrap_or(JsonField::Other);
                return Ok(JsonKey {
                    field,
                    fingerprint,
                    scalar_count,
                });
            }
            let scalar = if byte == b'\\' {
                self.position += 1;
                self.escape_scalar()?
            } else if byte <= 31 {
                return Err(CompatibilityReason::UnknownAuthenticationShape);
            } else if byte <= 127 {
                self.position += 1;
                char::from(byte)
            } else {
                let remaining = std::str::from_utf8(&self.bytes[self.position..])
                    .map_err(|_| CompatibilityReason::UnknownAuthenticationShape)?;
                let scalar = remaining
                    .chars()
                    .next()
                    .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
                self.position += scalar.len_utf8();
                scalar
            };
            scalar_count = scalar_count
                .checked_add(1)
                .filter(|count| *count <= MAX_KEY_SCALARS)
                .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
            fingerprint ^= u64::from(scalar as u32);
            fingerprint = fingerprint.wrapping_mul(PRIME);
            for (_, expected, matches) in &mut candidates {
                *matches &= expected.next() == Some(scalar);
            }
        }
    }

    fn nonempty_string(&mut self) -> Result<bool, CompatibilityReason> {
        self.nonempty_string_span().map(|_| true)
    }

    fn nonempty_string_span(&mut self) -> Result<(usize, usize), CompatibilityReason> {
        if self.bytes.get(self.position) != Some(&b'"') {
            return Err(CompatibilityReason::UnknownAuthenticationShape);
        }
        self.position += 1;
        let start = self.position;
        let mut non_whitespace = false;
        loop {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
            match byte {
                b'"' => {
                    let end = self.position;
                    self.position += 1;
                    return non_whitespace
                        .then_some((start, end))
                        .ok_or(CompatibilityReason::UnknownAuthenticationShape);
                }
                b'\\' => {
                    self.position += 1;
                    let scalar = self.escape_scalar()?;
                    if !scalar.is_whitespace() {
                        non_whitespace = true;
                    }
                }
                0..=31 => return Err(CompatibilityReason::UnknownAuthenticationShape),
                32..=127 => {
                    non_whitespace |= !byte.is_ascii_whitespace();
                    self.position += 1;
                }
                _ => {
                    let remaining = std::str::from_utf8(&self.bytes[self.position..])
                        .map_err(|_| CompatibilityReason::UnknownAuthenticationShape)?;
                    let scalar = remaining
                        .chars()
                        .next()
                        .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
                    non_whitespace |= !scalar.is_whitespace();
                    self.position += scalar.len_utf8();
                }
            }
        }
    }

    fn skip_string(&mut self) -> Result<(), CompatibilityReason> {
        if self.bytes.get(self.position) != Some(&b'"') {
            return Err(CompatibilityReason::UnknownAuthenticationShape);
        }
        self.position += 1;
        loop {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(());
                }
                b'\\' => {
                    self.position += 1;
                    let _ = self.escape_scalar()?;
                }
                0..=31 => return Err(CompatibilityReason::UnknownAuthenticationShape),
                32..=127 => self.position += 1,
                _ => {
                    let remaining = std::str::from_utf8(&self.bytes[self.position..])
                        .map_err(|_| CompatibilityReason::UnknownAuthenticationShape)?;
                    let scalar = remaining
                        .chars()
                        .next()
                        .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
                    self.position += scalar.len_utf8();
                }
            }
        }
    }

    fn escape_scalar(&mut self) -> Result<char, CompatibilityReason> {
        let escaped = *self
            .bytes
            .get(self.position)
            .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
        self.position += 1;
        match escaped {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{8}'),
            b'f' => Ok('\u{c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => {
                let first = self.hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if self.bytes.get(self.position..self.position + 2) != Some(b"\\u") {
                        return Err(CompatibilityReason::UnknownAuthenticationShape);
                    }
                    self.position += 2;
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(CompatibilityReason::UnknownAuthenticationShape);
                    }
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(CompatibilityReason::UnknownAuthenticationShape);
                } else {
                    u32::from(first)
                };
                char::from_u32(scalar).ok_or(CompatibilityReason::UnknownAuthenticationShape)
            }
            _ => Err(CompatibilityReason::UnknownAuthenticationShape),
        }
    }

    fn hex_quad(&mut self) -> Result<u16, CompatibilityReason> {
        let digits = self
            .bytes
            .get(self.position..self.position + 4)
            .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
        let mut value = 0_u16;
        for digit in digits {
            value = value
                .checked_mul(16)
                .and_then(|current| {
                    digit
                        .to_ascii_lowercase()
                        .checked_sub(b'0')
                        .and_then(|offset| match offset {
                            0..=9 => Some(current + u16::from(offset)),
                            49..=54 => Some(current + u16::from(offset - 39)),
                            _ => None,
                        })
                })
                .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
        }
        self.position += 4;
        Ok(value)
    }

    fn literal(&mut self, value: &[u8]) -> Result<(), CompatibilityReason> {
        if self.bytes.get(self.position..self.position + value.len()) != Some(value) {
            return Err(CompatibilityReason::UnknownAuthenticationShape);
        }
        self.position += value.len();
        Ok(())
    }

    fn number(&mut self) -> Result<(), CompatibilityReason> {
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        match self.bytes.get(self.position) {
            Some(b'0') => {
                self.position += 1;
                if self
                    .bytes
                    .get(self.position)
                    .is_some_and(u8::is_ascii_digit)
                {
                    return Err(CompatibilityReason::UnknownAuthenticationShape);
                }
            }
            Some(b'1'..=b'9') => {
                self.position += 1;
                while self
                    .bytes
                    .get(self.position)
                    .is_some_and(u8::is_ascii_digit)
                {
                    self.position += 1;
                }
            }
            _ => return Err(CompatibilityReason::UnknownAuthenticationShape),
        }
        if self.bytes.get(self.position) == Some(&b'.') {
            self.position += 1;
            let fraction_start = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == fraction_start {
                return Err(CompatibilityReason::UnknownAuthenticationShape);
            }
        }
        if self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b'e' | b'E'))
        {
            self.position += 1;
            if self
                .bytes
                .get(self.position)
                .is_some_and(|byte| matches!(byte, b'+' | b'-'))
            {
                self.position += 1;
            }
            let exponent_start = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == exponent_start {
                return Err(CompatibilityReason::UnknownAuthenticationShape);
            }
        }
        Ok(())
    }
}

pub fn classify(bytes: &[u8]) -> Result<(&'static str, &'static str), CompatibilityReason> {
    std::str::from_utf8(bytes).map_err(|_| CompatibilityReason::UnknownAuthenticationShape)?;
    let shape = Parser { bytes, position: 0 }.parse()?;
    let api = shape.api_key.is_some();
    let oauth = shape.tokens
        && shape.id_token
        && shape.access_token.is_some()
        && shape.refresh_token
        && shape.account_id;
    match (api, oauth) {
        (true, false) => Ok(("api_key", "OPENAI_API_KEY:string")),
        (false, true) => Ok((
            "oauth",
            "tokens:{id_token,access_token,refresh_token,account_id}:string",
        )),
        _ => Err(CompatibilityReason::UnknownAuthenticationShape),
    }
}

pub(crate) fn authorization_span(
    bytes: &[u8],
) -> Result<(&'static str, (usize, usize)), CompatibilityReason> {
    std::str::from_utf8(bytes).map_err(|_| CompatibilityReason::UnknownAuthenticationShape)?;
    let shape = (Parser { bytes, position: 0 }).parse()?;
    let oauth = shape.tokens
        && shape.id_token
        && shape.access_token.is_some()
        && shape.refresh_token
        && shape.account_id;
    match (shape.api_key, oauth) {
        (Some(span), false) => Ok(("api_key", span)),
        (None, true) => Ok(("oauth", shape.access_token.expect("checked above"))),
        _ => Err(CompatibilityReason::UnknownAuthenticationShape),
    }
}
