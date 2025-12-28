use std::fmt;

#[derive(Debug, Clone)]
pub enum RaikoError {
    InvalidBlobOption(String),
}

impl fmt::Display for RaikoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RaikoError::InvalidBlobOption(msg) => write!(f, "InvalidBlobOption: {}", msg),
        }
    }
}

impl std::error::Error for RaikoError {}

pub type RaikoResult<T> = Result<T, RaikoError>;

