//! Frames between the shell and `boxed serve`: a 4-byte little-endian length, then that many bytes of UTF-8 JSON (an object).

use std::fmt;
use std::io::{self, Read};

use serde_json::Value;

/// The sidecar refuses a request frame above this size, answers once and exits.
pub const MAX_REQUEST: usize = 1024 * 1024;
/// The sidecar never sends a reply above this size.
pub const MAX_REPLY: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The stream ended inside a frame.
    Truncated,
    /// The length is above the cap; the body is not read.
    TooLarge,
    /// The body is not UTF-8, not JSON, or not a JSON object.
    BadJson,
    Io(io::ErrorKind),
}

impl fmt::Display for FrameError {
    /// Fixed texts: an error never carries a piece of a frame.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FrameError::Truncated => "truncated frame",
            FrameError::TooLarge => "frame too large",
            FrameError::BadJson => "bad json",
            FrameError::Io(_) => "i/o error",
        })
    }
}

impl std::error::Error for FrameError {}

/// The bytes of one frame: length header and compact JSON. `cap` limits the JSON body.
pub fn encode(value: &Value, cap: usize) -> Result<Vec<u8>, FrameError> {
    if !value.is_object() {
        return Err(FrameError::BadJson);
    }
    let body = serde_json::to_vec(value).map_err(|_| FrameError::BadJson)?;
    if body.len() > cap {
        return Err(FrameError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(4 + body.len());
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// One frame from `reader`; `None` when the stream ended cleanly before the first byte of a frame.
pub fn read_frame<R: Read>(reader: &mut R, cap: usize) -> Result<Option<Value>, FrameError> {
    let mut header = [0u8; 4];
    match fill(reader, &mut header)? {
        0 => return Ok(None),
        4 => {}
        _ => return Err(FrameError::Truncated),
    }
    let size = u32::from_le_bytes(header) as usize;
    if size > cap {
        return Err(FrameError::TooLarge); // the body stays unread, and is never allocated
    }
    let mut body = vec![0u8; size];
    if fill(reader, &mut body)? < size {
        return Err(FrameError::Truncated);
    }
    match serde_json::from_slice::<Value>(&body) {
        Ok(value @ Value::Object(_)) => Ok(Some(value)),
        _ => Err(FrameError::BadJson),
    }
}

/// Reads until `buf` is full or the stream ends, and says how many bytes it got (a pipe may hand them out in pieces).
fn fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, FrameError> {
    let mut got = 0;
    while got < buf.len() {
        match reader.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameError::Io(e.kind())),
        }
    }
    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    /// A reader that hands out one byte per call, like a slow pipe.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.0[0];
            self.0 = &self.0[1..];
            Ok(1)
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn encode_writes_a_little_endian_length_then_compact_utf8_json() {
        let value = json!({"id": 1, "cmd": "ping"});
        let bytes = encode(&value, MAX_REQUEST).unwrap();
        let body = &bytes[4..];
        assert_eq!(&bytes[..4], &(body.len() as u32).to_le_bytes());
        assert_eq!(body.len(), r#"{"cmd":"ping","id":1}"#.len(), "compact: no spaces");
        assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), value);
    }

    #[test]
    fn encode_keeps_non_ascii_text_as_utf8() {
        let bytes = encode(&json!({"text": "Иван"}), MAX_REQUEST).unwrap();
        assert!(bytes.windows(8).any(|w| w == "Иван".as_bytes()));
    }

    #[test]
    fn encode_refuses_a_body_above_the_cap_and_a_value_that_is_not_an_object() {
        let big = json!({"text": "x".repeat(100)});
        assert_eq!(encode(&big, 50), Err(FrameError::TooLarge));
        assert_eq!(encode(&json!([1]), MAX_REQUEST), Err(FrameError::BadJson));
    }

    #[test]
    fn a_frame_survives_a_round_trip() {
        let value = json!({"id": 7, "ok": true, "text": "Привет, мир \u{1F4E6}", "n": [1, 2, 3]});
        let bytes = encode(&value, MAX_REQUEST).unwrap();
        assert_eq!(read_frame(&mut Cursor::new(bytes), MAX_REQUEST), Ok(Some(value)));
    }

    #[test]
    fn frames_follow_each_other_and_the_stream_ends_cleanly() {
        let mut bytes = encode(&json!({"id": 1}), MAX_REQUEST).unwrap();
        bytes.extend(encode(&json!({"id": 2}), MAX_REQUEST).unwrap());
        let mut reader = Cursor::new(bytes);
        assert_eq!(read_frame(&mut reader, MAX_REQUEST), Ok(Some(json!({"id": 1}))));
        assert_eq!(read_frame(&mut reader, MAX_REQUEST), Ok(Some(json!({"id": 2}))));
        assert_eq!(read_frame(&mut reader, MAX_REQUEST), Ok(None));
    }

    #[test]
    fn a_pipe_that_hands_out_one_byte_at_a_time_still_gives_whole_frames() {
        let bytes = encode(&json!({"id": 3, "text": "slow"}), MAX_REQUEST).unwrap();
        assert_eq!(read_frame(&mut Trickle(&bytes), MAX_REQUEST), Ok(Some(json!({"id": 3, "text": "slow"}))));
    }

    #[test]
    fn a_stream_cut_inside_the_header_or_the_body_is_truncated() {
        for cut in 1..4 {
            assert_eq!(read_frame(&mut Cursor::new(vec![9u8; cut]), MAX_REQUEST), Err(FrameError::Truncated));
        }
        let mut bytes = frame(br#"{"id":1}"#);
        bytes.truncate(bytes.len() - 1);
        assert_eq!(read_frame(&mut Cursor::new(bytes), MAX_REQUEST), Err(FrameError::Truncated));
    }

    #[test]
    fn a_length_above_the_cap_is_refused_before_the_body_is_read() {
        let mut bytes = ((MAX_REQUEST + 1) as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        let mut reader = Cursor::new(bytes);
        assert_eq!(read_frame(&mut reader, MAX_REQUEST), Err(FrameError::TooLarge));
        assert_eq!(reader.position(), 4, "only the header was consumed");
        // a length that cannot be real is refused the same way, without allocating it
        let mut reader = Cursor::new(u32::MAX.to_le_bytes().to_vec());
        assert_eq!(read_frame(&mut reader, MAX_REPLY), Err(FrameError::TooLarge));
    }

    #[test]
    fn a_length_equal_to_the_cap_is_allowed() {
        let body = format!(r#"{{"t":"{}"}}"#, "x".repeat(60));
        let bytes = frame(body.as_bytes());
        assert!(matches!(read_frame(&mut Cursor::new(bytes), body.len()), Ok(Some(_))));
    }

    #[test]
    fn a_body_that_is_not_a_json_object_is_bad_json() {
        let cases: [&[u8]; 7] = [b"", b"not json", b"[1,2]", b"42", b"\"text\"", b"\xff\xfe{}", b"\xef\xbb\xbf{}"];
        for body in cases {
            assert_eq!(read_frame(&mut Cursor::new(frame(body)), MAX_REQUEST), Err(FrameError::BadJson), "{body:?}");
        }
    }

    #[test]
    fn a_body_nested_far_too_deep_is_bad_json_not_a_crash() {
        let body = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
        assert_eq!(read_frame(&mut Cursor::new(frame(body.as_bytes())), MAX_REQUEST), Err(FrameError::BadJson));
    }

    #[test]
    fn error_texts_are_fixed_and_never_quote_the_frame() {
        let secret = "ivan.petrov@example.com";
        let body = format!("{{\"text\": \"{secret}\" oops");
        let err = read_frame(&mut Cursor::new(frame(body.as_bytes())), MAX_REQUEST).unwrap_err();
        assert!(!format!("{err} {err:?}").contains(secret));
        assert_eq!(err.to_string(), "bad json");
        assert_eq!(FrameError::Truncated.to_string(), "truncated frame");
        assert_eq!(FrameError::TooLarge.to_string(), "frame too large");
    }

    #[test]
    fn a_read_error_is_reported_with_its_kind_only() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "ivan.petrov@example.com"))
            }
        }
        let err = read_frame(&mut Broken, MAX_REQUEST).unwrap_err();
        assert_eq!(err, FrameError::Io(io::ErrorKind::BrokenPipe));
        assert!(!err.to_string().contains("ivan"));
    }
}
