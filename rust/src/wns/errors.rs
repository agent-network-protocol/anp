use thiserror::Error;

#[derive(Debug, Error)]
#[error("{message}")]
pub struct WnsError {
    pub message: String,
    pub status_code: u16,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct HandleValidationError {
    pub message: String,
    pub status_code: u16,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct HandleNotFoundError {
    pub message: String,
    pub status_code: u16,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct HandleGoneError {
    pub message: String,
    pub status_code: u16,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct HandleMovedError {
    pub message: String,
    pub status_code: u16,
    pub redirect_url: String,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct HandleResolutionError {
    pub message: String,
    pub status_code: u16,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct HandleBindingError {
    pub message: String,
    pub status_code: u16,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct WbaUriParseError {
    pub message: String,
    pub status_code: u16,
}
