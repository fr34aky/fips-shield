//! A minimal JSON writer.
//!
//! The UI emits a handful of fixed shapes and parses none, so serde
//! would be a large dependency for one direction of a job this size.
//! Everything here is escaping, which is the part that has to be right.

/// Append `s` as a quoted JSON string.
///
/// Escapes the two characters that would end or extend the string, plus
/// every C0 control. Log lines reach this straight from disk and are
/// attacker-influenced — a bare newline or quote in a User-Agent would
/// otherwise break out of the string and corrupt the document.
pub fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Builds a JSON object, tracking whether a separator is due.
pub struct Obj {
    pub buf: String,
    first: bool,
}

impl Obj {
    pub fn new() -> Self {
        Obj {
            buf: String::from("{"),
            first: true,
        }
    }

    fn key(&mut self, k: &str) {
        if !self.first {
            self.buf.push(',');
        }
        self.first = false;
        push_str(&mut self.buf, k);
        self.buf.push(':');
    }

    pub fn str(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k);
        push_str(&mut self.buf, v);
        self
    }

    pub fn num(&mut self, k: &str, v: u64) -> &mut Self {
        self.key(k);
        self.buf.push_str(&v.to_string());
        self
    }

    pub fn bool(&mut self, k: &str, v: bool) -> &mut Self {
        self.key(k);
        self.buf.push_str(if v { "true" } else { "false" });
        self
    }

    /// Insert an already-serialised value (array or object).
    pub fn raw(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k);
        self.buf.push_str(v);
        self
    }

    pub fn done(&mut self) -> String {
        let mut s = std::mem::take(&mut self.buf);
        s.push('}');
        s
    }
}

/// Serialise an iterator of already-serialised values as an array.
pub fn arr<I: IntoIterator<Item = String>>(items: I) -> String {
    let mut out = String::from("[");
    for (i, it) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&it);
    }
    out.push(']');
    out
}

/// Serialise an iterator of strings as an array of JSON strings.
pub fn str_arr<'a, I: IntoIterator<Item = &'a str>>(items: I) -> String {
    let mut out = String::from("[");
    for (i, it) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_str(&mut out, it);
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_what_would_break_out_of_a_string() {
        let mut s = String::new();
        push_str(&mut s, "a\"b\\c\nd\te\u{1}f");
        assert_eq!(s, r#""a\"b\\c\nd\te\u0001f""#);
    }

    #[test]
    fn a_log_line_with_a_quote_stays_one_string() {
        // A User-Agent is attacker-controlled and lands in the access
        // log verbatim; it must not be able to add fields to the object
        // that carries it.
        let mut s = String::new();
        push_str(&mut s, r#"","admin":true,"x":""#);
        assert!(s.starts_with('"') && s.ends_with('"'));
        let inner = &s[1..s.len() - 1];
        // No quote in the body terminates the string early: each is
        // preceded by its escaping backslash.
        assert!(inner.contains('"'), "test input must contain quotes");
        for (i, _) in inner.match_indices('"') {
            assert!(inner[..i].ends_with('\\'), "unescaped quote at {i}");
        }
    }

    #[test]
    fn object_and_array_shapes() {
        let mut o = Obj::new();
        o.str("a", "1").num("b", 2).bool("c", true);
        assert_eq!(o.done(), r#"{"a":"1","b":2,"c":true}"#);
        assert_eq!(arr(vec!["1".into(), "2".into()]), "[1,2]");
        assert_eq!(str_arr(vec!["x", "y"]), r#"["x","y"]"#);
        assert_eq!(Obj::new().done(), "{}");
    }
}
