pub type Result<T> = std::result::Result<T, KprunError>;
#[derive(Debug, thiserror::Error)]
pub enum KprunError {
    #[error("{0}")]
    Msg(String),
}
