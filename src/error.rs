#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    #[error("Unauthorized")]
    Unauthorized,

    #[error("{0}")]
    Custom(String),
    #[error("{0}")]
    Wrapped(String),
    #[error("Database [sqlx]: {0}")]
    Sql(String),
    #[error("JsonWebToken: {0}")]
    Jwt(String),
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.kind, f)
    }
}
impl std::error::Error for Error {}

#[cfg(feature="ssr")]
impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        Self { kind: ErrorKind::Sql(value.to_string()) }
    }
}
#[cfg(feature="ssr")]
impl From<jsonwebtoken::errors::Error> for Error {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        Self { kind: ErrorKind::Jwt(value.to_string()) }
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self { kind: ErrorKind::Custom(value.to_string()) }
    }
}
impl From<String> for Error {
    fn from(value: String) -> Self {
        Self { kind: ErrorKind::Custom(value) }
    }
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    pub fn custom(msg: impl std::fmt::Display) -> Self {
        Self { kind: ErrorKind::Custom(msg.to_string()) }
    }

    pub fn wrap(e: impl std::error::Error) -> Self {
        Self { kind: ErrorKind::Wrapped(e.to_string()) }
    }

    pub fn unauthorized() -> Self {
        Self { kind: ErrorKind::Unauthorized }
    }
}