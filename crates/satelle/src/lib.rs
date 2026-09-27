//! Internal modules used by the `satelle` executable.
//!
//! The crate is published to support `cargo install satelle`. These modules do
//! not define a stable Rust library API.

#[doc(hidden)]
pub mod command_group;
#[doc(hidden)]
pub mod core;
#[doc(hidden)]
pub mod host;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_contract;
#[doc(hidden)]
#[path = "transport_api/mod.rs"]
pub mod transport;
