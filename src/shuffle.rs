// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::HwError;
use rand::SeedableRng;
use rand::{Rng, RngCore};
use rand_chacha::ChaCha12Rng;

/// A variant of Durstenfeld's algorithm, which shuffles from lowest index to highest.
#[derive(Debug, Default)]
pub(crate) struct Durstenfeld {}

/// A trait defining `Shuffler` objects that can be used for shuffling data
/// in various manners
pub(crate) trait Shuffler<T> {
    /// Shuffle the passed data in-place using randomness from the provided
    /// `RngCore`. `shuffle_len` defines how many elements will be shuffled.
    fn shuffle<R>(
        &mut self,
        data: &mut Vec<T>,
        shuffle_len: usize,
        rng: &mut R,
    ) -> Result<(), HwError>
    where
        T: Clone,
        R: RngCore + ?Sized;
}

impl<T> Shuffler<T> for Durstenfeld {
    fn shuffle<R>(
        &mut self,
        data: &mut Vec<T>,
        shuffle_len: usize,
        rng: &mut R,
    ) -> Result<(), HwError>
    where
        T: Clone,
        R: RngCore + ?Sized,
    {
        let dlen = data.len();
        if dlen < shuffle_len {
            return Err(HwError::ShuffleError);
        }

        for i in 0..shuffle_len {
            // TODO: document the range implementation,
            //       so we can replicate the logic to other programming languages too.
            let j = rng.gen_range(i..dlen);
            data.swap(i, j);
        }
        Ok(())
    }
}

/// Deterministic Durstenfeld shuffling to return a list of random indexes in a range [0,max_num)
/// It is required for shuffling the leaves in the sparse Merkle tree accumulator of HashWires.
pub(crate) fn deterministic_index_shuffling(
    indexes_required: usize,
    max_num: usize,
    seed: [u8; 32],
) -> Result<Vec<usize>, HwError> {
    let mut input = (0..max_num).collect();
    let mut rng = ChaCha12Rng::from_seed(seed);
    let mut durstenfeld = Durstenfeld::default();
    durstenfeld.shuffle(&mut input, indexes_required, &mut rng)?;
    input.truncate(indexes_required);
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_durstenfeld() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha12Rng;

        let seed = [2u8; 32];
        let mut durstenfeld = Durstenfeld::default();

        // Test for full length.
        let mut input = vec![1, 2, 3, 4, 5];
        let mut rng = ChaCha12Rng::from_seed(seed);
        let length = input.len();
        durstenfeld.shuffle(&mut input, length, &mut rng).unwrap();
        assert_eq!(&input, &[5, 3, 4, 1, 2]);

        // Test for 2 elements only.
        let mut input = vec![1, 2, 3, 4, 5];
        let mut rng = ChaCha12Rng::from_seed(seed);
        let length = 2;
        durstenfeld.shuffle(&mut input, length, &mut rng).unwrap();
        assert_eq!(&input, &[5, 3, 2, 4, 1]);
    }
}
