use rand::{RngCore, SeedableRng, Rng};
use rand_chacha::ChaCha12Rng;

/// A variant of Durstenfeld's algorithm, which shuffles from lowest index to highest.
#[derive(Debug, Default)]
pub struct Durstenfeld {}

/// A trait defining `Shuffler` objects that can be used for shuffling data
/// in various manners
pub trait Shuffler<T> {
    /// Shuffle the passed data in-place using randomness from the provided
    /// `RngCore`. `shuffle_len` defines how many elements will be shuffled.
    fn shuffle<R>(&mut self, data: &mut Vec<T>, shuffle_len: &usize, rng: &mut R) -> Result<(), &str>
    where
        T: Clone,
        R: RngCore + ?Sized;
}

impl<T> Shuffler<T> for Durstenfeld {
    // TODO: consider error types
    fn shuffle<R>(&mut self, data: &mut Vec<T>, shuffle_len: &usize, rng: &mut R) -> Result<(), &str>
    where
        T: Clone,
        R: RngCore + ?Sized,
    {
        let dlen = data.len();
        if dlen < *shuffle_len {
            return Err("shuffle_len can be larger than input data length");
        }

        for i in 0..*shuffle_len {
            // TODO:
            let j = rng.gen_range(i, dlen);
            data.swap(i, j);
        }
        Ok(())
    }
}

#[test]
fn test_deterministic_durstenfeld() {
    let seed = [2u8; 32];
    let mut fy = Durstenfeld::default();

    // Test for full length.
    let mut input = vec![1, 2, 3, 4, 5];
    let mut rng = ChaCha12Rng::from_seed(seed);
    let length = &input.len();
    fy.shuffle(&mut input, length, &mut rng);
    assert_eq!(&input, &[5, 3, 4, 1, 2]);

    // Test for 2 elements only.
    let mut input = vec![1, 2, 3, 4, 5];
    let mut rng = ChaCha12Rng::from_seed(seed);
    let length = &2;
    fy.shuffle(&mut input, length, &mut rng);
    assert_eq!(&input, &[5, 3, 2, 4, 1]);
}
