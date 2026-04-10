use axum::{extract::Request, middleware::Next, response::Response};
use http::HeaderValue;

/// `<cargo_version>+<git_hash>` or just `<cargo_version>` if `NOX_BUILD_HASH` is unset.
pub fn build_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        let base = env!("CARGO_PKG_VERSION");
        match option_env!("NOX_BUILD_HASH") {
            Some(hash) if !hash.is_empty() => format!("{base}+{hash}"),
            _ => base.to_string(),
        }
    })
}

pub async fn version_header(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    if let Ok(val) = HeaderValue::from_str(build_version()) {
        response.headers_mut().insert("x-nox-version", val);
    }
    response
}
