use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use thiserror::Error;

use crate::types::ApiResponse;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Bad request: {0}")]
    BadRequestWithHint(String, String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Blockchain error: {0}")]
    Blockchain(String),
}

impl ApiError {
    pub fn bad_request_with_hint(msg: impl Into<String>, hint: impl Into<String>) -> Self {
        Self::BadRequestWithHint(msg.into(), hint.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message, hint) = match &self {
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Invalid or missing API key".to_string(),
                Some("Include 'Authorization: Bearer YOUR_API_KEY' header"),
            ),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone(), None),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone(), None),
            ApiError::Conflict(msg) => (
                StatusCode::CONFLICT,
                msg.clone(),
                Some("The resource already exists or conflicts with existing data"),
            ),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone(), None),
            ApiError::BadRequestWithHint(msg, hint) => (StatusCode::BAD_REQUEST, msg.clone(), Some(hint.as_str())),
            ApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded".to_string(),
                Some("Wait before making more requests"),
            ),
            ApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                Some("Please try again later or contact support"),
            ),
            ApiError::Blockchain(msg) => (
                StatusCode::BAD_GATEWAY,
                msg.clone(),
                Some("Blockchain verification failed"),
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

pub type ApiResult<T> = Result<T, ApiError>;
