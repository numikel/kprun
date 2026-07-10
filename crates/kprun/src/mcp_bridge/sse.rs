//! Minimal Server-Sent Events parser shared by both MCP HTTP transports.

use std::io::{BufRead, BufReader, Read};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// Event type; SSE default is "message".
    pub event: String,
    /// `data:` lines joined with '\n'.
    pub data: String,
    pub id: Option<String>,
}

pub struct SseParser<R: Read> {
    reader: BufReader<R>,
    /// Reused line buffer: this is the per-frame hot path of the
    /// long-lived bridge, so per-line allocations add up.
    raw: String,
}

impl<R: Read> SseParser<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            raw: String::new(),
        }
    }
}

impl<R: Read> Iterator for SseParser<R> {
    type Item = std::io::Result<SseEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut event = String::from("message");
        // Single accumulator instead of Vec<String> + join: subsequent
        // `data:` lines append '\n' then the value. `has_data` carries
        // the one bit Vec::is_empty() provided — "no data field seen"
        // vs "empty data" (the latter still emits an event).
        let mut data = String::new();
        let mut has_data = false;
        let mut id: Option<String> = None;
        loop {
            self.raw.clear();
            match self.reader.read_line(&mut self.raw) {
                Ok(0) => return None, // EOF discards any partial event (SSE spec)
                Ok(_) => {}
                Err(e) => return Some(Err(e)),
            }
            let line = self.raw.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                if !has_data {
                    // Blank line with no accumulated data: reset and keep reading.
                    event.clear();
                    event.push_str("message");
                    id = None;
                    continue;
                }
                return Some(Ok(SseEvent { event, data, id }));
            }
            if line.starts_with(':') {
                continue; // comment / keepalive
            }
            let (field, value) = match line.split_once(':') {
                Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                None => (line, ""),
            };
            match field {
                "event" => {
                    event.clear();
                    event.push_str(value);
                }
                "data" => {
                    if has_data {
                        data.push('\n');
                    }
                    data.push_str(value);
                    has_data = true;
                }
                "id" => id = Some(value.to_string()),
                _ => {} // `retry` and unknown fields ignored
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(input: &str) -> Vec<SseEvent> {
        SseParser::new(input.as_bytes())
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn parses_single_message_event() {
        let evs = events("data: {\"x\":1}\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event, "message");
        assert_eq!(evs[0].data, "{\"x\":1}");
        assert_eq!(evs[0].id, None);
    }

    #[test]
    fn joins_multiline_data() {
        let evs = events("data: a\ndata: b\n\n");
        assert_eq!(evs[0].data, "a\nb");
    }

    #[test]
    fn parses_event_type_and_id() {
        let evs = events("event: endpoint\nid: 42\ndata: /messages?sid=1\n\n");
        assert_eq!(evs[0].event, "endpoint");
        assert_eq!(evs[0].id.as_deref(), Some("42"));
        assert_eq!(evs[0].data, "/messages?sid=1");
    }

    #[test]
    fn skips_comments_and_unknown_fields() {
        let evs = events(": keepalive\nretry: 500\ndata: x\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "x");
    }

    #[test]
    fn handles_crlf_line_endings() {
        let evs = events("data: x\r\n\r\n");
        assert_eq!(evs[0].data, "x");
    }

    #[test]
    fn multiple_events_and_eof_discards_partial() {
        let evs = events("data: one\n\ndata: two\n\ndata: partial-no-blank-line");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].data, "one");
        assert_eq!(evs[1].data, "two");
    }

    #[test]
    fn value_without_leading_space_is_kept() {
        let evs = events("data:tight\n\n");
        assert_eq!(evs[0].data, "tight");
    }

    #[test]
    fn empty_data_line_still_emits_event() {
        let evs = events("data:\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "");
    }
}
