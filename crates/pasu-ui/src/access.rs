//! Who may use the UI.
//!
//! The UI decides `Ask` verdicts and, with the dashboard, edits the kernel
//! allowlist. Anything that can reach its port could do both, and the agent
//! being guarded can: the kernel layer always lets loopback through, so a
//! `curl` to `127.0.0.1` from an allowed shell tool approves the agent's own
//! pending calls. So can any web page the operator has open, with a plain
//! cross-site form post.
//!
//! Every request therefore carries a token generated at startup. The operator
//! opens the printed URL once; the token moves into a `SameSite=Strict`,
//! `HttpOnly` cookie and out of the address bar. A browser never attaches that
//! cookie to a request another site started, and a process that never saw the
//! startup line has nothing to send.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

const COOKIE: &str = "pasu_ui";
const QUERY_KEY: &str = "token";
const TOKEN_BYTES: usize = 32;

/// The token every UI request must present.
#[derive(Clone)]
pub struct Access {
    token: String,
}

/// The OS gave no randomness, so no token could be made.
#[derive(Debug)]
pub struct AccessError(getrandom::Error);

impl std::fmt::Display for AccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot generate a UI access token: {}", self.0)
    }
}

impl std::error::Error for AccessError {}

impl Access {
    /// A fresh token from the OS random source.
    ///
    /// # Errors
    /// When the OS cannot supply randomness. The UI must not start without a
    /// token rather than start open.
    pub fn generate() -> Result<Self, AccessError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(AccessError)?;
        Ok(Self {
            token: bytes.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }

    /// The URL to print for the operator. Opening it once is the login.
    #[must_use]
    pub fn login_url(&self, addr: std::net::SocketAddr) -> String {
        format!("http://{addr}/?{QUERY_KEY}={}", self.token)
    }

    fn matches(&self, candidate: &str) -> bool {
        constant_time_eq(self.token.as_bytes(), candidate.as_bytes())
    }
}

/// The middleware: exchange a URL token for the cookie, otherwise require the
/// cookie, and refuse any state change another origin started.
pub(crate) async fn require(State(access): State<Access>, req: Request, next: Next) -> Response {
    if let Some(token) = query_token(req.uri().query()) {
        if !access.matches(token) {
            return refuse();
        }
        return login(&access, req.uri().path());
    }
    if !cookie_token(req.headers()).is_some_and(|t| access.matches(t)) {
        return refuse();
    }
    if req.method() != Method::GET && req.method() != Method::HEAD && cross_origin(req.headers()) {
        return refuse();
    }
    next.run(req).await
}

fn login(access: &Access, path: &str) -> Response {
    let cookie = format!(
        "{COOKIE}={}; HttpOnly; SameSite=Strict; Path=/",
        access.token
    );
    let Ok(cookie) = HeaderValue::from_str(&cookie) else {
        return refuse();
    };
    // `//host` would be a protocol-relative redirect off this origin.
    let path = if path.starts_with("//") { "/" } else { path };
    let location = HeaderValue::from_str(path).unwrap_or(HeaderValue::from_static("/"));
    let mut resp = StatusCode::SEE_OTHER.into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie);
    resp.headers_mut().insert(header::LOCATION, location);
    resp
}

fn refuse() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(
            "pasu-ui: open the URL printed when the UI started (it carries the access token)",
        ))
        .unwrap_or_else(|_| StatusCode::UNAUTHORIZED.into_response())
}

fn query_token(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix(QUERY_KEY)?.strip_prefix('='))
}

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='))
}

/// An `Origin` that names a different host than the one addressed. Absent is
/// not cross-origin: non-browser clients send none, and they still need the
/// cookie.
fn cross_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return false;
    };
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    let origin_host = origin.to_str().ok().and_then(|o| {
        o.strip_prefix("http://")
            .or_else(|| o.strip_prefix("https://"))
    });
    match (origin_host, host) {
        (Some(o), Some(h)) => o != h,
        _ => true,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_long() {
        let a = Access::generate().unwrap();
        let b = Access::generate().unwrap();
        assert_ne!(a.token, b.token);
        assert_eq!(a.token.len(), TOKEN_BYTES * 2);
    }

    #[test]
    fn a_prefix_of_the_token_does_not_match() {
        let a = Access::generate().unwrap();
        assert!(a.matches(&a.token.clone()));
        assert!(!a.matches(&a.token[..10]));
        assert!(!a.matches(""));
    }

    #[test]
    fn origin_rules() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8789"));
        assert!(!cross_origin(&h), "no Origin: non-browser client");
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:8789"),
        );
        assert!(!cross_origin(&h));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(cross_origin(&h));
        h.insert(header::ORIGIN, HeaderValue::from_static("null"));
        assert!(
            cross_origin(&h),
            "opaque origin (sandboxed frame) is foreign"
        );
    }
}
