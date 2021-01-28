//! A list of error types which are produced during an execution of the protocol
use displaydoc::Display;
use thiserror::Error;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Debug, Display, Error)]
pub enum HWError {
    /// Error in shuffling, shuffle_len can be larger than input data length
    ShuffleError,
}
