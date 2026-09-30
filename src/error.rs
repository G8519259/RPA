use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Bad(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("内部错误: {0}")]
    Internal(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Any(#[from] anyhow::Error),
}

impl AppError {
    pub fn bad(m: impl Into<String>) -> Self {
        Self::Bad(m.into())
    }
    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self::Unauthorized(m.into())
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::Forbidden(m.into())
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::NotFound(m.into())
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::Internal(m.into())
    }
}

#[derive(Serialize)]
struct ErrBody {
    ok: bool,
    data: Option<()>,
    error: String,
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Bad(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Internal(_) | AppError::Db(_) | AppError::Any(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self) -> HttpResponse {
        let msg = match self {
            AppError::Db(e) => {
                tracing::error!(?e, "db error");
                "数据库错误".to_string()
            }
            AppError::Any(e) => {
                tracing::error!(?e, "internal error");
                format!("内部错误: {e}")
            }
            other => other.to_string(),
        };
        HttpResponse::build(self.status_code()).json(ErrBody {
            ok: false,
            data: None,
            error: msg,
        })
    }
}

pub type AppResult<T> = Result<T, AppError>;
