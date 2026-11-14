//! Error types for sigstore-oidc

use thiserror::Error;

/// Errors that can occur in OIDC operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A request to the identity provider could not be sent or its response
    /// could not be read (connection, TLS, timeout). Retrying may succeed.
    #[error("identity provider request failed: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The identity provider answered the token exchange with a non-success
    /// HTTP status.
    #[error("token exchange failed with HTTP {status}: {message}")]
    Status {
        /// The HTTP status code
        status: u16,
        /// The status reason
        message: String,
    },

    /// The identity provider refused the authorization request; the payload
    /// is its reason.
    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),

    /// The OAuth callback's `state` did not match the request, which may be a
    /// cross-site request forgery attempt.
    #[error("OAuth state mismatch (possible CSRF attack)")]
    StateMismatch,

    /// The browser did not complete the OAuth flow in time.
    #[error("timed out waiting for the browser callback after {seconds} seconds")]
    CallbackTimedOut {
        /// How long the flow waited
        seconds: u64,
    },

    /// Detecting ambient CI credentials failed.
    #[error("failed to detect ambient credentials: {0}")]
    Ambient(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The identity token is malformed.
    #[error("token error: {0}")]
    Token(String),

    /// Any other failure in the OAuth flow (local callback server, malformed
    /// callback or token response).
    #[error("OAuth error: {0}")]
    OAuth(String),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result type for OIDC operations
pub type Result<T> = std::result::Result<T, Error>;
