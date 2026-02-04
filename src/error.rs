//! Error types for AMAI Identity Service

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

use crate::types::ApiResponse;

/// API error types
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Bad request: {0}")]
    BadRequestWithHint(String, String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    #[error("Replay detected: nonce already used")]
    ReplayDetected,

    #[error("Timestamp expired or too far in future")]
    TimestampInvalid,

    #[error("Sigchain error: {0}")]
    SigchainError(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn bad_request_with_hint(msg: impl Into<String>, hint: impl Into<String>) -> Self {
        Self::BadRequestWithHint(msg.into(), hint.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }

    pub fn signature(msg: impl Into<String>) -> Self {
        Self::SignatureError(msg.into())
    }

    pub fn sigchain(msg: impl Into<String>) -> Self {
        Self::SigchainError(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message, hint) = match &self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone(), None),
            Self::BadRequestWithHint(msg, hint) => {
                (StatusCode::BAD_REQUEST, msg.clone(), Some(hint.as_str()))
            }
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Signature verification required".to_string(),
                Some("Sign request payload with your private key"),
            ),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone(), None),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone(), None),
            Self::Conflict(msg) => (
                StatusCode::CONFLICT,
                msg.clone(),
                Some("The resource already exists"),
            ),
            Self::SignatureError(msg) => (
                StatusCode::UNAUTHORIZED,
                msg.clone(),
                Some("Ensure signature is valid base64 and matches payload"),
            ),
            Self::ReplayDetected => (
                StatusCode::UNAUTHORIZED,
                "Replay detected: nonce already used".to_string(),
                Some("Generate a fresh nonce for each request"),
            ),
            Self::TimestampInvalid => (
                StatusCode::UNAUTHORIZED,
                "Timestamp invalid".to_string(),
                Some("Ensure timestamp is within 5 minutes of server time"),
            ),
            Self::SigchainError(msg) => (
                StatusCode::BAD_REQUEST,
                msg.clone(),
                Some("Check sigchain integrity"),
            ),
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded".to_string(),
                Some("Wait before making more requests"),
            ),
            Self::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                Some("Please try again later"),
            ),
        };

        let body = if let Some(h) = hint {
            ApiResponse::<()>::error_with_hint(message, h)
        } else {
            ApiResponse::<()>::error(message)
        };

        (status, Json(body)).into_response()
    }
}

/// Result type alias for API operations
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_constructors() {
        let e = ApiError::bad_request("test");
        assert!(matches!(e, ApiError::BadRequest(_)));

        let e = ApiError::not_found("test");
        assert!(matches!(e, ApiError::NotFound(_)));

        let e = ApiError::signature("test");
        assert!(matches!(e, ApiError::SignatureError(_)));
    }

    #[test]
    fn test_error_display() {
        let e = ApiError::BadRequest("invalid input".into());
        assert_eq!(e.to_string(), "Bad request: invalid input");

        let e = ApiError::ReplayDetected;
        assert_eq!(e.to_string(), "Replay detected: nonce already used");
    }
}
