//! A deliberately small HTTP/1.1 server.
//!
//! Why not a framework: this serves a handful of fixed GET routes to a
//! loopback listener and parses no request bodies. Pulling a runtime and
//! its dependency tree into a security tool for that is a poor trade —
//! the whole surface here is a request line, a header skip, and a
//! response write, which is auditable in one sitting.
//!
//! The rules that keep it small are enforced, not assumed:
//!
//!   * GET only. Anything else is 405 before routing.
//!   * A fixed route table. Paths are matched, never mapped onto the
//!     filesystem, so there is no traversal to defend against.
//!   * Hard caps on the request line, header count, and total header
//!     bytes, so a peer cannot make the server allocate without bound.
//!   * A read timeout, so a connection that opens and says nothing is
//!     reaped instead of holding a thread.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const MAX_REQUEST_LINE: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADERS: usize = 100;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Request {
    pub path: String,
    pub query: Vec<(String, String)>,
}

impl Request {
    pub fn param(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl Response {
    pub fn json(body: String) -> Self {
        Response {
            status: 200,
            content_type: "application/json; charset=utf-8",
            body,
        }
    }

    pub fn html(body: String) -> Self {
        Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body,
        }
    }

    pub fn error(status: u16, msg: &str) -> Self {
        let mut o = crate::json::Obj::new();
        o.str("error", msg);
        Response {
            status,
            content_type: "application/json; charset=utf-8",
            body: o.done(),
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Percent-decode, treating `+` as a space. Invalid escapes are left
/// alone rather than rejected — this only feeds lookups that are
/// themselves validated against a whitelist.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b[i]);
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(p), String::new()),
        })
        .collect()
}

fn read_request(stream: &TcpStream) -> Result<Request, Response> {
    let mut r = BufReader::new(stream);

    let mut line = String::new();
    // take() bounds the read: without it a peer sending an endless
    // stream with no newline would grow this String until the process
    // dies.
    let n = (&mut r)
        .take(MAX_REQUEST_LINE as u64)
        .read_line(&mut line)
        .map_err(|_| Response::error(400, "unreadable request"))?;
    if n == 0 {
        return Err(Response::error(400, "empty request"));
    }
    if n >= MAX_REQUEST_LINE && !line.ends_with('\n') {
        return Err(Response::error(413, "request line too long"));
    }

    let mut parts = line.trim_end().split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" {
        return Err(Response::error(405, "only GET is served"));
    }

    // Drain headers. They are not used — nothing here varies by header
    // — but they must be consumed for the response to be well-framed.
    let mut total = 0usize;
    for i in 0.. {
        if i >= MAX_HEADERS {
            return Err(Response::error(413, "too many headers"));
        }
        let mut h = String::new();
        let n = (&mut r)
            .take(MAX_REQUEST_LINE as u64)
            .read_line(&mut h)
            .map_err(|_| Response::error(400, "unreadable headers"))?;
        if n == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        total += n;
        if total > MAX_HEADER_BYTES {
            return Err(Response::error(413, "headers too large"));
        }
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, parse_query(q)),
        None => (target, Vec::new()),
    };
    Ok(Request {
        path: percent_decode(path),
        query,
    })
}

fn write_response(mut stream: &TcpStream, resp: &Response) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; \
         script-src 'unsafe-inline'; connect-src 'self'\r\n\
         \r\n",
        resp.status,
        reason(resp.status),
        resp.content_type,
        resp.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(resp.body.as_bytes())?;
    stream.flush()
}

/// Serve until killed. `handler` maps a request to a response; it is
/// called on a worker thread, one per connection.
pub fn serve<F>(listener: TcpListener, handler: F) -> !
where
    F: Fn(&Request) -> Response + Send + Sync + 'static,
{
    let handler = std::sync::Arc::new(handler);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let handler = handler.clone();
        // A thread per connection is fine at this scale: the listener is
        // loopback and the client is one dashboard polling a few
        // endpoints. The timeouts below are what stop a stuck peer from
        // holding one forever.
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
            let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
            let resp = match read_request(&stream) {
                Ok(req) => handler(&req),
                Err(e) => e,
            };
            let _ = write_response(&stream, &resp);
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });
    }
    unreachable!("incoming() never returns None")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_percent_and_plus() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("%2e%2e%2f"), "../");
        // A malformed escape is passed through, not silently eaten.
        assert_eq!(percent_decode("100%zz"), "100%zz");
        assert_eq!(percent_decode("trailing%"), "trailing%");
    }

    #[test]
    fn parses_query_pairs() {
        let q = parse_query("service=web&n=50&flag");
        assert_eq!(q.len(), 3);
        assert_eq!(q[0], ("service".into(), "web".into()));
        assert_eq!(q[2], ("flag".into(), String::new()));
        assert!(parse_query("").is_empty());
    }

    #[test]
    fn request_param_lookup() {
        let r = Request {
            path: "/api/logs".into(),
            query: parse_query("service=web&n=10"),
        };
        assert_eq!(r.param("service"), Some("web"));
        assert_eq!(r.param("missing"), None);
    }
}
