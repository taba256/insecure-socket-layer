// 参照: https://tex2e.github.io/rfc-translater/html/rfc6101.html

mod cipher;
pub mod error;
mod fragment;
mod msg;
pub mod server;
mod types;

pub type Result<T> = std::result::Result<T, error::Error>;

pub mod internal {
    pub mod msg {
        pub use crate::msg::*;
    }
    pub mod types {
        pub use crate::types::*;
    }
}
