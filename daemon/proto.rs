// SPDX-License-Identifier: GPL-2.0-only
//! buildutil daemon wire protocol.
//!
//! The protocol deliberately has no serde dependency: a four-byte big-endian
//! length prefix carries one small JSON object.  Event JSON is carried as an
//! opaque string so the existing JSONL event grammar remains the authority.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

pub const PROTOCOL_VERSION: u32 = 3;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const FRAME_TIMEOUT_PREFIX: &str = "daemon frame timeout:";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub protocol_version: u32,
    pub binary_identity: String,
    pub repo_root: Vec<u8>,
    pub state_root: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub argv: Vec<String>,
    pub cwd: Vec<u8>,
    pub env: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestRecord {
    pub id: String,
    pub argv: Vec<String>,
    pub outcome: String,
    pub code: Option<i32>,
    pub duration_ms: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReport {
    pub watcher_health: String,
    pub events_since_baseline: usize,
    pub history: Vec<RequestRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Handshake(Handshake),
    Request(Request),
    Status,
    StatusReport(StatusReport),
    Cancel,
    Stop { force: bool },
    Event(String),
    Output { stream: String, bytes: Vec<u8> },
    Queued { position: usize },
    Exit { code: i32 },
    Error(String),
    Stopped,
}

pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame) -> Result<(), String> {
    let payload = encode(frame);
    if payload.len() > MAX_FRAME_BYTES {
        return Err(format!("daemon frame exceeds {} bytes", MAX_FRAME_BYTES));
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(|e| format!("daemon frame header: {e}"))?;
    writer
        .write_all(payload.as_bytes())
        .map_err(|e| format!("daemon frame body: {e}"))?;
    writer
        .flush()
        .map_err(|e| format!("daemon frame flush: {e}"))
}

/// `Ok(None)` is a clean EOF before a frame starts.  EOF after a header or
/// body is corruption, not a normal disconnect, so callers can cleanly abort
/// the associated request.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Frame>, String> {
    let mut header = [0u8; 4];
    let first = loop {
        match reader.read(&mut header) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => break result,
        }
    };
    match first {
        Ok(0) => return Ok(None),
        Ok(n) => read_rest(reader, &mut header[n..], "header", true)?,
        Err(error) => return Err(read_error("header", error)),
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(format!(
            "daemon frame length {len} exceeds {MAX_FRAME_BYTES}"
        ));
    }
    let mut payload = vec![0u8; len];
    read_rest(reader, &mut payload, "body", true)?;
    let text =
        std::str::from_utf8(&payload).map_err(|_| "daemon frame is not UTF-8".to_string())?;
    decode(text).map(Some)
}

fn read_rest<R: Read>(
    reader: &mut R,
    bytes: &mut [u8],
    part: &str,
    frame_started: bool,
) -> Result<(), String> {
    let mut filled = 0;
    while filled < bytes.len() {
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => return Err(format!("truncated daemon frame {part}")),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if frame_started
                    && matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
            {
                return Err(format!("daemon partial frame {part} timeout: {error}"));
            }
            Err(error) => return Err(read_error(part, error)),
        }
    }
    Ok(())
}

fn read_error(part: &str, error: io::Error) -> String {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        format!("{FRAME_TIMEOUT_PREFIX} {part}: {error}")
    } else {
        format!("daemon frame {part}: {error}")
    }
}

pub fn is_timeout_error(error: &str) -> bool {
    error.starts_with(FRAME_TIMEOUT_PREFIX)
}

fn encode(frame: &Frame) -> String {
    match frame {
        Frame::Handshake(handshake) => format!(
            "{{\"type\":\"handshake\",\"protocol_version\":{},\"binary_identity\":\"{}\",\"repo_root_bytes\":\"{}\",\"state_root_bytes\":\"{}\"}}",
            handshake.protocol_version,
            escape(&handshake.binary_identity),
            encode_bytes(&handshake.repo_root),
            encode_bytes(&handshake.state_root),
        ),
        Frame::Request(request) => format!(
            "{{\"type\":\"request\",\"id\":\"{}\",\"argv\":[{}],\"cwd_bytes\":\"{}\",\"env_bytes\":{{{}}}}}",
            escape(&request.id),
            request
                .argv
                .iter()
                .map(|value| format!("\"{}\"", escape(value)))
                .collect::<Vec<_>>()
                .join(","),
            encode_bytes(&request.cwd),
            request
                .env
                .iter()
                .map(|(key, value)| format!("\"{}\":\"{}\"", escape(key), encode_bytes(value)))
                .collect::<Vec<_>>()
                .join(","),
        ),
        Frame::Status => "{\"type\":\"status\"}".to_string(),
        Frame::StatusReport(report) => format!(
            "{{\"type\":\"status-report\",\"watcher_health\":\"{}\",\"events_since_baseline\":{},\"history\":[{}]}}",
            escape(&report.watcher_health),
            report.events_since_baseline,
            report
                .history
                .iter()
                .map(record_json)
                .collect::<Vec<_>>()
                .join(","),
        ),
        Frame::Cancel => "{\"type\":\"cancel\"}".to_string(),
        Frame::Stop { force } => format!("{{\"type\":\"stop\",\"force\":{}}}", usize::from(*force)),
        Frame::Event(line) => format!("{{\"type\":\"event\",\"line\":\"{}\"}}", escape(line)),
        Frame::Output { stream, bytes } => format!(
            "{{\"type\":\"output\",\"stream\":\"{}\",\"bytes\":\"{}\"}}",
            escape(stream),
            encode_bytes(bytes)
        ),
        Frame::Queued { position } => format!("{{\"type\":\"queued\",\"position\":{position}}}"),
        Frame::Exit { code } => format!("{{\"type\":\"exit\",\"code\":{code}}}"),
        Frame::Error(message) => {
            format!("{{\"type\":\"error\",\"message\":\"{}\"}}", escape(message))
        }
        Frame::Stopped => "{\"type\":\"stopped\"}".to_string(),
    }
}

fn record_json(record: &RequestRecord) -> String {
    format!(
        "{{\"id\":\"{}\",\"argv\":[{}],\"outcome\":\"{}\",\"has_code\":{},\"code\":{},\"duration_ms\":{}}}",
        escape(&record.id),
        record
            .argv
            .iter()
            .map(|arg| format!("\"{}\"", escape(arg)))
            .collect::<Vec<_>>()
            .join(","),
        escape(&record.outcome),
        usize::from(record.code.is_some()),
        record.code.unwrap_or(0),
        record.duration_ms,
    )
}

fn decode(text: &str) -> Result<Frame, String> {
    let value = Parser::new(text).parse()?;
    let object = value.object()?;
    let ty = object.string("type")?;
    match ty.as_str() {
        "handshake" => Ok(Frame::Handshake(Handshake {
            protocol_version: object
                .number("protocol_version")?
                .try_into()
                .map_err(|_| "daemon protocol version is out of range")?,
            binary_identity: object.string("binary_identity")?,
            repo_root: decode_bytes(&object.string("repo_root_bytes")?)?,
            state_root: decode_bytes(&object.string("state_root_bytes")?)?,
        })),
        "request" => {
            let argv = object
                .array("argv")?
                .iter()
                .map(Value::as_string)
                .collect::<Result<Vec<_>, _>>()?;
            let env = object
                .object("env_bytes")?
                .0
                .iter()
                .map(|(key, value)| Ok((key.clone(), decode_bytes(&value.as_string()?)?)))
                .collect::<Result<BTreeMap<_, _>, String>>()?;
            Ok(Frame::Request(Request {
                id: object.string("id")?,
                argv,
                cwd: decode_bytes(&object.string("cwd_bytes")?)?,
                env,
            }))
        }
        "status" => Ok(Frame::Status),
        "status-report" => Ok(Frame::StatusReport(StatusReport {
            watcher_health: object.string("watcher_health")?,
            events_since_baseline: object
                .number("events_since_baseline")?
                .try_into()
                .map_err(|_| "daemon status event count is out of range")?,
            history: object
                .array("history")?
                .iter()
                .map(parse_record)
                .collect::<Result<Vec<_>, _>>()?,
        })),
        "cancel" => Ok(Frame::Cancel),
        "stop" => Ok(Frame::Stop {
            force: object.number("force")? != 0,
        }),
        "event" => Ok(Frame::Event(object.string("line")?)),
        "output" => Ok(Frame::Output {
            stream: object.string("stream")?,
            bytes: decode_bytes(&object.string("bytes")?)?,
        }),
        "queued" => Ok(Frame::Queued {
            position: object
                .number("position")?
                .try_into()
                .map_err(|_| "daemon queue position is out of range")?,
        }),
        "exit" => Ok(Frame::Exit {
            code: object
                .signed("code")?
                .try_into()
                .map_err(|_| "daemon exit code is out of range")?,
        }),
        "error" => Ok(Frame::Error(object.string("message")?)),
        "stopped" => Ok(Frame::Stopped),
        other => Err(format!("unknown daemon frame type `{other}`")),
    }
}

fn parse_record(value: &Value) -> Result<RequestRecord, String> {
    let object = value.object()?;
    let argv = object
        .array("argv")?
        .iter()
        .map(Value::as_string)
        .collect::<Result<Vec<_>, _>>()?;
    let has_code = object.number("has_code")? != 0;
    Ok(RequestRecord {
        id: object.string("id")?,
        argv,
        outcome: object.string("outcome")?,
        code: has_code
            .then(|| object.signed("code"))
            .transpose()?
            .map(|code| {
                code.try_into()
                    .map_err(|_| "daemon history code is out of range")
            })
            .transpose()?,
        duration_ms: object.number("duration_ms")? as u128,
    })
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

pub(crate) fn encode_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn decode_bytes(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("daemon byte encoding has odd length".to_string());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| "invalid daemon byte encoding".to_string())?;
            let lo = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| "invalid daemon byte encoding".to_string())?;
            Ok((hi * 16 + lo) as u8)
        })
        .collect()
}

#[derive(Clone, Debug)]
enum Value {
    String(String),
    Number(i64),
    Array(Vec<Value>),
    Object(Object),
}

impl Value {
    fn as_string(&self) -> Result<String, String> {
        match self {
            Self::String(value) => Ok(value.clone()),
            _ => Err("daemon JSON value is not a string".to_string()),
        }
    }
    fn object(&self) -> Result<&Object, String> {
        match self {
            Self::Object(value) => Ok(value),
            _ => Err("daemon JSON root is not an object".to_string()),
        }
    }
}

#[derive(Clone, Debug)]
struct Object(BTreeMap<String, Value>);

impl Object {
    fn value(&self, key: &str) -> Result<&Value, String> {
        self.0
            .get(key)
            .ok_or_else(|| format!("daemon JSON misses `{key}`"))
    }
    fn string(&self, key: &str) -> Result<String, String> {
        self.value(key)?.as_string()
    }
    fn number(&self, key: &str) -> Result<u64, String> {
        match self.value(key)? {
            Value::Number(value) if *value >= 0 => Ok(*value as u64),
            _ => Err(format!("daemon JSON `{key}` is not an unsigned number")),
        }
    }
    fn signed(&self, key: &str) -> Result<i64, String> {
        match self.value(key)? {
            Value::Number(value) => Ok(*value),
            _ => Err(format!("daemon JSON `{key}` is not a number")),
        }
    }
    fn array(&self, key: &str) -> Result<&Vec<Value>, String> {
        match self.value(key)? {
            Value::Array(value) => Ok(value),
            _ => Err(format!("daemon JSON `{key}` is not an array")),
        }
    }
    fn object(&self, key: &str) -> Result<&Object, String> {
        self.value(key)?.object()
    }
}

struct Parser<'a> {
    text: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text: text.as_bytes(),
            at: 0,
        }
    }
    fn parse(mut self) -> Result<Value, String> {
        let value = self.value()?;
        self.ws();
        if self.at == self.text.len() {
            Ok(value)
        } else {
            Err("trailing daemon JSON data".to_string())
        }
    }
    fn ws(&mut self) {
        while self.text.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }
    fn byte(&mut self, byte: u8) -> Result<(), String> {
        self.ws();
        if self.text.get(self.at) == Some(&byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!(
                "malformed daemon JSON: expected `{}`",
                byte as char
            ))
        }
    }
    fn value(&mut self) -> Result<Value, String> {
        self.ws();
        match self.text.get(self.at) {
            Some(b'\"') => Ok(Value::String(self.string()?)),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err("malformed daemon JSON value".to_string()),
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.byte(b'\"')?;
        let mut out = String::new();
        while let Some(&byte) = self.text.get(self.at) {
            self.at += 1;
            match byte {
                b'\"' => return Ok(out),
                b'\\' => {
                    let esc = *self
                        .text
                        .get(self.at)
                        .ok_or("truncated daemon JSON escape")?;
                    self.at += 1;
                    match esc {
                        b'\"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let digits = self
                                .text
                                .get(self.at..self.at + 4)
                                .ok_or("truncated daemon JSON unicode escape")?;
                            self.at += 4;
                            let text = std::str::from_utf8(digits)
                                .map_err(|_| "invalid daemon JSON unicode escape")?;
                            let code = u16::from_str_radix(text, 16)
                                .map_err(|_| "invalid daemon JSON unicode escape")?;
                            out.push(
                                char::from_u32(code as u32)
                                    .ok_or("invalid daemon JSON unicode scalar")?,
                            );
                        }
                        _ => return Err("invalid daemon JSON escape".to_string()),
                    }
                }
                byte if byte < 0x20 => {
                    return Err("control character in daemon JSON string".to_string());
                }
                byte if byte.is_ascii() => out.push(byte as char),
                _ => {
                    self.at -= 1;
                    let text = std::str::from_utf8(&self.text[self.at..])
                        .map_err(|_| "invalid UTF-8 in daemon JSON string")?;
                    let ch = text
                        .chars()
                        .next()
                        .ok_or("truncated UTF-8 in daemon JSON string")?;
                    out.push(ch);
                    self.at += ch.len_utf8();
                }
            }
        }
        Err("unterminated daemon JSON string".to_string())
    }
    fn number(&mut self) -> Result<Value, String> {
        self.ws();
        let start = self.at;
        if self.text.get(self.at) == Some(&b'-') {
            self.at += 1;
        }
        while self.text.get(self.at).is_some_and(u8::is_ascii_digit) {
            self.at += 1;
        }
        if start == self.at || (self.at == start + 1 && self.text[start] == b'-') {
            return Err("invalid daemon JSON number".to_string());
        }
        let text = std::str::from_utf8(&self.text[start..self.at])
            .map_err(|_| "invalid daemon JSON number")?;
        Ok(Value::Number(
            text.parse().map_err(|_| "invalid daemon JSON number")?,
        ))
    }
    fn array(&mut self) -> Result<Value, String> {
        self.byte(b'[')?;
        let mut values = Vec::new();
        self.ws();
        if self.text.get(self.at) == Some(&b']') {
            self.at += 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.ws();
            match self.text.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(values));
                }
                _ => return Err("malformed daemon JSON array".to_string()),
            }
        }
    }
    fn object(&mut self) -> Result<Value, String> {
        self.byte(b'{')?;
        let mut values = BTreeMap::new();
        self.ws();
        if self.text.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Ok(Value::Object(Object(values)));
        }
        loop {
            let key = self.string()?;
            self.byte(b':')?;
            let value = self.value()?;
            if values.insert(key, value).is_some() {
                return Err("duplicate daemon JSON key".to_string());
            }
            self.ws();
            match self.text.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(Object(values)));
                }
                _ => return Err("malformed daemon JSON object".to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(value: &str) -> Vec<u8> {
        value.as_bytes().to_vec()
    }

    fn realistic_request() -> Frame {
        Frame::Request(Request {
            id: "request-1".into(),
            argv: vec!["build".into(), "default".into(), "--timings".into()],
            cwd: bytes("/home/person/project"),
            env: BTreeMap::from([
                (
                    "BUILDUTIL_STORE".into(),
                    bytes("/home/person/project/.buildutil"),
                ),
                ("BUILDUTIL_RUSTC".into(), bytes("/opt/toolchain/bin/rustc")),
                ("BUILDUTIL_LINKER".into(), bytes("/opt/toolchain/bin/clang")),
                ("BUILDUTIL_STATCACHE_MAX_BYTES".into(), bytes("67108864")),
                (
                    "SDKROOT".into(),
                    bytes(
                        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
                    ),
                ),
                ("SOURCE_DATE_EPOCH".into(), bytes("1720000000")),
                (
                    "PATH".into(),
                    bytes("/opt/toolchain/bin:/usr/local/bin:/usr/bin:/bin"),
                ),
                ("HOME".into(), bytes("/Users/사용자")),
                ("TMPDIR".into(), bytes("/var/folders/test/T/")),
                ("TERM".into(), bytes("xterm-256color")),
                ("NO_COLOR".into(), bytes("1")),
            ]),
        })
    }

    #[test]
    fn frame_round_trip_handles_partial_io() {
        let frame = Frame::Request(Request {
            id: "partial".into(),
            argv: vec!["build".into(), "default".into()],
            cwd: bytes("/repo"),
            env: BTreeMap::from([("PATH".into(), bytes("/bin"))]),
        });
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        struct OneByte(Vec<u8>);
        impl Read for OneByte {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                out[0] = self.0.remove(0);
                Ok(1)
            }
        }
        assert_eq!(read_frame(&mut OneByte(bytes)).unwrap(), Some(frame));
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let mut bytes = ((MAX_FRAME_BYTES as u32) + 1).to_be_bytes().to_vec();
        bytes.extend_from_slice(b"x");
        assert!(read_frame(&mut &bytes[..]).unwrap_err().contains("exceeds"));
    }

    #[test]
    fn truncated_stream_is_rejected() {
        let mut bytes = 4u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        assert!(
            read_frame(&mut &bytes[..])
                .unwrap_err()
                .contains("truncated")
        );
    }

    #[test]
    fn timeout_errors_have_a_stable_classification() {
        struct TimedOut;
        impl Read for TimedOut {
            fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::TimedOut.into())
            }
        }
        let error = read_frame(&mut TimedOut).unwrap_err();
        assert!(is_timeout_error(&error));
    }

    #[test]
    fn timeout_after_partial_frame_is_not_retryable() {
        struct PartialThenTimeout {
            bytes: Vec<u8>,
            timed_out: bool,
        }
        impl Read for PartialThenTimeout {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.timed_out {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                self.timed_out = true;
                let count = self.bytes.len().min(out.len()).min(2);
                out[..count].copy_from_slice(&self.bytes[..count]);
                Ok(count)
            }
        }
        let error = read_frame(&mut PartialThenTimeout {
            bytes: 2u32.to_be_bytes().to_vec(),
            timed_out: false,
        })
        .unwrap_err();
        assert!(error.contains("partial frame"));
        assert!(!is_timeout_error(&error));
    }

    #[test]
    fn realistic_request_round_trips_in_memory() {
        let frame = realistic_request();
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        assert_eq!(read_frame(&mut &bytes[..]).unwrap(), Some(frame));
    }

    #[test]
    fn path_and_environment_bytes_round_trip_losslessly() {
        let frame = Frame::Request(Request {
            id: "non-utf8".into(),
            argv: vec!["build".into()],
            cwd: vec![b'/', b'r', 0xff],
            env: BTreeMap::from([("HOME".into(), vec![b'/', 0xfe])]),
        });
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &frame).unwrap();
        assert_eq!(read_frame(&mut &encoded[..]).unwrap(), Some(frame));

        let handshake = Frame::Handshake(Handshake {
            protocol_version: PROTOCOL_VERSION,
            binary_identity: "binary".into(),
            repo_root: vec![b'/', 0xfd],
            state_root: vec![b'/', 0xfc],
        });
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &handshake).unwrap();
        assert_eq!(read_frame(&mut &encoded[..]).unwrap(), Some(handshake));
    }

    #[test]
    fn watcher_status_round_trips_in_memory() {
        let frame = Frame::StatusReport(StatusReport {
            watcher_health: "healthy".into(),
            events_since_baseline: 0,
            history: vec![RequestRecord {
                id: "request-1".into(),
                argv: vec!["build".into(), "default".into()],
                outcome: "exit".into(),
                code: Some(0),
                duration_ms: 42,
            }],
        });
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        assert_eq!(read_frame(&mut &bytes[..]).unwrap(), Some(frame));
    }

    #[cfg(unix)]
    #[test]
    fn realistic_request_round_trips_over_client_server_socket_pair() {
        use std::os::unix::net::UnixStream;

        let frame = realistic_request();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = frame.clone();
        let sender = std::thread::spawn(move || write_frame(&mut client, &writer));
        assert_eq!(read_frame(&mut server).unwrap(), Some(frame));
        sender.join().unwrap().unwrap();
    }
}
