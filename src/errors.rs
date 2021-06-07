// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! A list of error types which are produced during an execution of the protocol
use displaydoc::Display;
use thiserror::Error;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Debug, Display, Error)]
pub enum HwError {
    /// Error in shuffling, shuffle_len can be larger than input data length
    ShuffleError,
    /// Error with generating inclusion proof for merkle tree
    InclusionProofError,
    /// Error encountered when converting seed to 32-byte string
    SeedLengthError,
    /// Verification of proof failed
    ProofVerificationError,
    /// Error in decoding merkle proof
    MerkleProofDecodingError,
    /// Proving value is bigger than the issued value
    MdpError,
    /// Error in serializing / deserializing bytestrings
    SerializationError,
}
