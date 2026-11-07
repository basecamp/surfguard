//! A small JSON reader for the conformance corpus and the IANA snapshots, so
//! neither the tests nor the generator need a dependency. It reads RFC 8259
//! documents into `Value` and fails on anything else.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(members) => Some(members),
            _ => None,
        }
    }
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = reader.value()?;
    reader.whitespace();
    if reader.at == reader.bytes.len() {
        Ok(value)
    } else {
        Err(reader.error("trailing characters"))
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn value(&mut self) -> Result<Value, String> {
        self.whitespace();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("value expected")),
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.at += 1;
        let mut members = BTreeMap::new();
        self.whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("member name expected"));
            }
            let name = self.string()?;
            self.whitespace();
            self.expect(b':')?;
            let value = self.value()?;
            if members.insert(name, value).is_some() {
                return Err(self.error("duplicate member name"));
            }
            self.whitespace();
            match self.next() {
                Some(b',') => {}
                Some(b'}') => return Ok(Value::Object(members)),
                _ => return Err(self.error("',' or '}' expected")),
            }
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.at += 1;
        let mut items = Vec::new();
        self.whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.whitespace();
            match self.next() {
                Some(b',') => {}
                Some(b']') => return Ok(Value::Array(items)),
                _ => return Err(self.error("',' or ']' expected")),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.at += 1;
        let mut text = String::new();
        loop {
            let start = self.at;
            while let Some(byte) = self.peek() {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.at += 1;
            }
            text.push_str(
                std::str::from_utf8(&self.bytes[start..self.at])
                    .map_err(|_| self.error("invalid UTF-8"))?,
            );
            match self.next() {
                Some(b'"') => return Ok(text),
                Some(b'\\') => text.push(self.escape()?),
                _ => return Err(self.error("unterminated string")),
            }
        }
    }

    fn escape(&mut self) -> Result<char, String> {
        match self.next() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\u{8}'),
            Some(b'f') => Ok('\u{c}'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => {
                let unit = self.hex4()?;
                if (0xd800..0xdc00).contains(&unit) {
                    if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                        return Err(self.error("unpaired surrogate"));
                    }
                    let low = self.hex4()?;
                    if !(0xdc00..0xe000).contains(&low) {
                        return Err(self.error("unpaired surrogate"));
                    }
                    let code = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                    char::from_u32(code).ok_or_else(|| self.error("invalid code point"))
                } else {
                    char::from_u32(unit).ok_or_else(|| self.error("unpaired surrogate"))
                }
            }
            _ => Err(self.error("invalid escape")),
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .bytes
            .get(self.at..self.at + 4)
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| self.error("four hex digits expected"))?;
        self.at += 4;
        u32::from_str_radix(digits, 16).map_err(|_| self.error("four hex digits expected"))
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.error("digit expected")),
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            self.required_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            self.required_digits()?;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).expect("ASCII digits");
        text.parse()
            .map(Value::Number)
            .map_err(|_| self.error("invalid number"))
    }

    fn required_digits(&mut self) -> Result<(), String> {
        if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.digits();
            Ok(())
        } else {
            Err(self.error("digit expected"))
        }
    }

    fn digits(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, String> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.next() == Some(byte) {
            Ok(())
        } else {
            Err(self.error(&format!("'{}' expected", byte as char)))
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek();
        self.at += usize::from(byte.is_some());
        byte
    }

    fn error(&self, message: &str) -> String {
        format!("{message} at byte {}", self.at)
    }
}
