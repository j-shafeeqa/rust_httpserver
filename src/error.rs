use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use crate::models::ApiResponse;

pub struct AppError(pub anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:?}", self.0);
        
        let error_message = self.0.to_string();
        let response = ApiResponse::<()>::error(error_message);
        
        (StatusCode::BAD_REQUEST, Json(response)).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;