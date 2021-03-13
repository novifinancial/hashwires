//! A library supplying paddable sparse Merkle tree.

pub mod error;
pub mod index;
pub mod node_template;
pub mod proof;
pub mod traits;
pub mod tree;
pub mod utils;
pub mod pad_secret;

#[cfg(test)]
mod tests;
