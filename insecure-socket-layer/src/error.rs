#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(std::io::Error),
    #[error(transparent)]
    DecodeError(crate::msg::codec::DecodeError),
    #[error("{0}")]
    Handshake(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<crate::msg::codec::DecodeError> for Error {
    fn from(e: crate::msg::codec::DecodeError) -> Error {
        Error::DecodeError(e)
    }
}
