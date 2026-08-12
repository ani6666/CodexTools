use std::collections::BTreeMap;

use codex_application::CompatibilityReason;

#[derive(Debug)]
enum JsonValue {
    Object(BTreeMap<String, JsonValue>),
    Array,
    String(String),
    Scalar,
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn parse(mut self) -> Result<JsonValue, CompatibilityReason> {
        self.ws();
        let value = self.value()?;
        self.ws();
        if self.position != self.bytes.len() {
            return Err(CompatibilityReason::UnknownAuthenticationShape);
        }
        Ok(value)
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
    fn value(&mut self) -> Result<JsonValue, CompatibilityReason> {
        self.ws();
        match self.bytes.get(self.position) {
            Some(b'{') => self.object(),
            Some(b'[') => {
                self.skip_array()?;
                Ok(JsonValue::Array)
            }
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(CompatibilityReason::UnknownAuthenticationShape),
        }
    }
    fn object(&mut self) -> Result<JsonValue, CompatibilityReason> {
        self.position += 1;
        self.ws();
        let mut values = BTreeMap::new();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(JsonValue::Object(values));
        }
        loop {
            let key = self.string()?;
            self.ws();
            if self.bytes.get(self.position) != Some(&b':') {
                return Err(CompatibilityReason::UnknownAuthenticationShape);
            }
            self.position += 1;
            let value = self.value()?;
            if values.insert(key, value).is_some() {
                return Err(CompatibilityReason::UnknownAuthenticationShape);
            }
            self.ws();
            match self.bytes.get(self.position) {
                Some(b',') => {
                    self.position += 1;
                    self.ws();
                }
                Some(b'}') => {
                    self.position += 1;
                    break;
                }
                _ => return Err(CompatibilityReason::UnknownAuthenticationShape),
            }
        }
        Ok(JsonValue::Object(values))
    }
    fn skip_array(&mut self) -> Result<(), CompatibilityReason> {
        self.position += 1;
        self.ws();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(());
        }
        loop {
            let _ = self.value()?;
            self.ws();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(());
                }
                _ => return Err(CompatibilityReason::UnknownAuthenticationShape),
            }
        }
    }
    fn string(&mut self) -> Result<String, CompatibilityReason> {
        if self.bytes.get(self.position) != Some(&b'"') {
            return Err(CompatibilityReason::UnknownAuthenticationShape);
        }
        self.position += 1;
        let mut result = String::new();
        while let Some(byte) = self.bytes.get(self.position).copied() {
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(result);
                }
                b'\\' => {
                    self.position += 1;
                    let escaped = *self
                        .bytes
                        .get(self.position)
                        .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
                    self.position += 1;
                    match escaped {
                        b'"' => result.push('"'),
                        b'\\' => result.push('\\'),
                        b'/' => result.push('/'),
                        b'b' => result.push('\u{8}'),
                        b'f' => result.push('\u{c}'),
                        b'n' => result.push('\n'),
                        b'r' => result.push('\r'),
                        b't' => result.push('\t'),
                        b'u' => {
                            let first = self.hex_quad()?;
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                if self.bytes.get(self.position..self.position + 2) != Some(b"\\u")
                                {
                                    return Err(CompatibilityReason::UnknownAuthenticationShape);
                                }
                                self.position += 2;
                                let second = self.hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(CompatibilityReason::UnknownAuthenticationShape);
                                }
                                0x1_0000
                                    + ((u32::from(first) - 0xd800) << 10)
                                    + (u32::from(second) - 0xdc00)
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err(CompatibilityReason::UnknownAuthenticationShape);
                            } else {
                                u32::from(first)
                            };
                            result.push(
                                char::from_u32(scalar)
                                    .ok_or(CompatibilityReason::UnknownAuthenticationShape)?,
                            );
                        }
                        _ => return Err(CompatibilityReason::UnknownAuthenticationShape),
                    }
                }
                0..=31 => return Err(CompatibilityReason::UnknownAuthenticationShape),
                32..=127 => {
                    result.push(char::from(byte));
                    self.position += 1;
                }
                _ => {
                    let remaining = std::str::from_utf8(&self.bytes[self.position..])
                        .map_err(|_| CompatibilityReason::UnknownAuthenticationShape)?;
                    let character = remaining
                        .chars()
                        .next()
                        .ok_or(CompatibilityReason::UnknownAuthenticationShape)?;
                    result.push(character);
                    self.position += character.len_utf8();
                }
            }
        }
        Err(CompatibilityReason::UnknownAuthenticationShape)
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
    fn literal(&mut self, value: &[u8]) -> Result<JsonValue, CompatibilityReason> {
        if self.bytes.get(self.position..self.position + value.len()) != Some(value) {
            return Err(CompatibilityReason::UnknownAuthenticationShape);
        }
        self.position += value.len();
        Ok(JsonValue::Scalar)
    }
    fn number(&mut self) -> Result<JsonValue, CompatibilityReason> {
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
        Ok(JsonValue::Scalar)
    }
}

pub fn classify(bytes: &[u8]) -> Result<(&'static str, &'static str), CompatibilityReason> {
    std::str::from_utf8(bytes).map_err(|_| CompatibilityReason::UnknownAuthenticationShape)?;
    let value = Parser { bytes, position: 0 }.parse()?;
    let JsonValue::Object(root) = value else {
        return Err(CompatibilityReason::UnknownAuthenticationShape);
    };
    let api = matches!(root.get("OPENAI_API_KEY"), Some(JsonValue::String(value)) if !value.trim().is_empty());
    let oauth = match root.get("tokens") {
        Some(JsonValue::Object(tokens)) => ["id_token","access_token","refresh_token","account_id"].iter().all(|key| matches!(tokens.get(*key), Some(JsonValue::String(value)) if !value.trim().is_empty())),
        _ => false,
    };
    match (api, oauth) {
        (true, false) => Ok(("api_key", "OPENAI_API_KEY:string")),
        (false, true) => Ok((
            "oauth",
            "tokens:{id_token,access_token,refresh_token,account_id}:string",
        )),
        _ => Err(CompatibilityReason::UnknownAuthenticationShape),
    }
}
