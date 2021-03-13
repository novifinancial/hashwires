use crate::hashwires::PlrPaddingSize;
use crate::traits::Hash;
use digest::Digest;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

pub const LEAF_SALT: &[u8; 32] = b"01234567890123456789012345678901";
pub const TOP_SALT: &[u8; 32] = b"11234567890123456789012345678901";
pub const PADDING_SALT: &[u8; 32] = b"21234567890123456789012345678901";
pub const SMTREE_PADDING_SALT: &[u8; 32] = b"31234567890123456789012345678901";

/// Output padding node + PLR accumulator
#[inline]
pub fn plr_accumulator<D: Hash>(
    seed: &[u8],
    list: &[[u8; 32]],
    max_length: usize,
    desired_length: usize,
) -> (
    GenericArray<u8, PlrPaddingSize>,
    Option<GenericArray<u8, PlrPaddingSize>>,
) {
    let mut hasher = D::new();
    let mut plr_path_node = if list.len() < max_length {
        hasher.update(PADDING_SALT);
        hasher.update(seed);
        let result = &hasher.finalize_reset()[..PlrPaddingSize::to_usize()];
        hasher.update(&result);
        Some(GenericArray::clone_from_slice(&result))
    } else {
        None
    };

    let mut output = vec![0; PlrPaddingSize::to_usize()];
    list.iter().enumerate().for_each(|(i, v)| {
        if i != 0 {
            hasher.update(&output);
            if i == list.len() - desired_length {
                plr_path_node = Some(GenericArray::clone_from_slice(
                    &output[..PlrPaddingSize::to_usize()],
                ));
            }
        }
        hasher.update(v);
        output.copy_from_slice(hasher.finalize_reset().as_slice());
    });

    (GenericArray::clone_from_slice(&output), plr_path_node)
}

/// Computes a hash chain using a seed and number of iterations.
#[inline]
pub fn hash_chain<D: Hash>(seed: &[u8], iterations: usize) -> [u8; 32] {
    // TODO: reuse hashers in single threaded applications, i.e. via finalize_reset()
    let mut output = [0u8; 32];
    let mut hasher = D::new();
    output.copy_from_slice(seed);
    for _i in 0..iterations {
        hasher.update(&output);
        output.copy_from_slice(hasher.finalize_reset().as_slice());
    }
    output
}

/// Return all of the elements of the hash chain, where seed is at index = 0.
#[inline]
pub fn full_hash_chain<D: Hash>(seed: &[u8], size: usize) -> Vec<[u8; 32]> {
    let mut hasher = D::new();
    let mut output = Vec::with_capacity(size);
    let mut temp = [0; 32];
    temp.copy_from_slice(seed);
    output.push(temp);
    for _i in 1..size {
        hasher.update(&temp);
        temp.copy_from_slice(hasher.finalize_reset().as_slice());
        output.push(temp);
    }
    output
}

pub fn compute_hash_chains<D: Hash>(
    seed: &[u8],
    size: usize,
    base: u32,
    most_significant_digit: u8,
) -> Vec<Vec<[u8; 32]>> {
    let mut output: Vec<Vec<[u8; 32]>> = Vec::with_capacity(size);
    let seeds = generate_subseeds::<D, D::OutputSize>(LEAF_SALT, seed, size);

    // optimization: first chain might be shorter (up to most_significant_digit in selected base)
    let first_chain = full_hash_chain::<D>(&seeds[0], most_significant_digit as usize + 1);
    output.push(first_chain);

    for elem in seeds.iter().skip(1) {
        output.push(full_hash_chain::<D>(elem, base as usize));
    }
    output
}

/// Simple KDF hash(salt, i, seed)
/// TODO: make it more generic to work for any seed size
#[inline]
pub fn salted_hash<D: Hash>(salt: &[u8], seed: &[u8]) -> [u8; 32] {
    let mut hasher = D::new();
    hasher.update(salt);
    hasher.update(seed);
    let mut output = [0; 32];
    output.copy_from_slice(hasher.finalize().as_slice());
    output
}

#[inline]
pub fn generate_subseeds<D: Hash, N: ArrayLength<u8>>(
    salt: &[u8],
    seed: &[u8],
    num_of_seeds: usize,
) -> Vec<GenericArray<u8, N>> {
    let mut hasher = D::new();
    let mut seeds = Vec::with_capacity(num_of_seeds);
    for i in 0..num_of_seeds {
        hasher.update(salt);
        hasher.update(i.to_le_bytes());
        hasher.update(seed);
        let arr = GenericArray::clone_from_slice(&hasher.finalize_reset()[..N::to_usize()]);
        seeds.push(arr);
    }
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hasher as Blake3;

    #[test]
    fn test_hash_chain() {
        use blake3::Hasher as Blake3;

        let hash_chain_output = hash_chain::<Blake3>(b"01234567890123456789012345678901", 3);
        assert_eq!(
            hex::encode(hash_chain_output),
            "9dce6dd3c7e70a6e5052fe1626b97d5ff50f59764513950df43faf76f15efc5c"
        );
    }

    #[test]
    fn test_full_hash_chain() {
        use blake3::Hasher as Blake3;

        let chain = full_hash_chain::<Blake3>(b"01234567890123456789012345678901", 3);

        assert_eq!(chain.len(), 3);
        assert_eq!(
            hex::encode(chain[0]),
            "3031323334353637383930313233343536373839303132333435363738393031"
        );
        assert_eq!(
            hex::encode(chain[1]),
            "1952cbec4fc2d03d99a121bdae24cb8333a6e8944ccf1f5ac4c3b4f4ee744edf"
        );
        assert_eq!(
            hex::encode(chain[2]),
            "df327beebc850ce697953eb99ecdf8f2979b5f103a73c45aa4b1415192032ef6"
        );
    }

    #[test]
    fn test_compute_hashchains() {
        let seed = [0u8; 32];
        let chains = compute_hash_chains::<Blake3>(&seed, 3, 4, 2);
        assert_eq!(chains.len(), 3);
        assert_eq!(chains[0].len(), 3);
        assert_eq!(chains[1].len(), 4);
        assert_eq!(chains[2].len(), 4);
    }

    #[test]
    fn test_plr() {
        let seed = [0u8; 32];
        let values = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let plr = plr_accumulator::<Blake3>(&seed, &values, 3, 3);
        assert!(plr.1.is_none());
        assert_eq!(
            hex::encode(plr.0),
            "0082c1dc66375f9ab20e8d699d48d9903fcae459330c03215a9909faaa0cf183"
        );

        let plr = plr_accumulator::<Blake3>(&seed, &values, 4, 3);
        assert!(plr.1.is_some());
        assert_eq!(
            hex::encode(plr.0),
            "4accab47316eb7c538da7b940ce45e459572fd194ce25f4d5d42ab753cbf3fb4"
        );
        assert_eq!(
            hex::encode(plr.0),
            "4accab47316eb7c538da7b940ce45e459572fd194ce25f4d5d42ab753cbf3fb4"
        );
    }
}
