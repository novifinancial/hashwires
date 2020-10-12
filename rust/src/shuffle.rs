use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

#[derive(Debug, Default)]
pub struct FisherYates {
    buffer: [u8; std::mem::size_of::<usize>()],
}

impl FisherYates {
    fn gen_range<R>(&mut self, top: usize, rng: &mut R) -> usize
    where
        R: RngCore + ?Sized,
    {
        const USIZE_BYTES: usize = std::mem::size_of::<usize>();
        let bit_width = USIZE_BYTES * 8 - top.leading_zeros() as usize;
        let byte_count = (bit_width - 1) / 8 + 1;
        loop {
            rng.fill_bytes(&mut self.buffer[..byte_count]);
            let result = usize::from_le_bytes(self.buffer);
            let result = result & ((1 << bit_width) - 1);
            if result < top {
                break result;
            }
        }
    }
}

/// A trait defining `Shuffler` objects that can be used for shuffling data
/// in various manners
pub trait Shuffler<T> {
    /// Shuffle the passed data in-place using randomness from the provided
    /// `RngCore`.
    fn shuffle<R>(&mut self, data: &mut Vec<T>, rng: &mut R) -> Result<(), &str>
    where
        T: Clone,
        R: RngCore + ?Sized;
}

impl<T> Shuffler<T> for FisherYates {
    fn shuffle<R>(&mut self, data: &mut Vec<T>, rng: &mut R) -> Result<(), &str>
    where
        T: Clone,
        R: RngCore + ?Sized,
    {
        for i in 1..data.len() {
            let j = self.gen_range(i, rng);
            data.swap(i, j);
        }
        Ok(())
    }
}

#[test]
fn test_deterministic_fisher_yates() {
    let seed = [0u8; 32];
    let mut rng = ChaCha12Rng::from_seed(seed);
    let mut fy = FisherYates::default();
    let mut input = vec![1, 2, 3, 4, 5];
    fy.shuffle(&mut input, &mut rng);
    assert_eq!(&input, &[2, 3, 5, 1, 4]);
}
