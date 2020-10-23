use blake3::Hasher as Blake3;
use digest::Digest;
use std::convert::TryFrom;

/// Computes a hash chain using a seed and number of iterations.
#[inline]
pub fn hash_chain<D: Digest>(seed: &[u8], iterations: usize, output: &mut [u8]) {
    // TODO: reuse hashers in single threaded applications, i.e. via finalize_reset()
    let mut hasher = D::new();
    output.copy_from_slice(seed);
    for _i in 0..iterations {
        hasher.update(&output);
        output.copy_from_slice(hasher.finalize_reset().as_slice());
    }
}

#[inline]
pub fn salted_hash<D: Digest>(salt: &[u8], seed: &[u8], output: &mut [u8]) {
    let mut hasher = D::new();
    hasher.update(salt);
    hasher.update(seed);
    output.copy_from_slice(hasher.finalize().as_slice());
}

/// Simple KDF hash(salt, i, seed)
/// TODO: make it more generic to work for any seed size
#[inline]
pub fn generate_subseeds<D: Digest>(salt: &[u8], seed: &[u8], num_of_seeds: usize) -> Vec<[u8; 32]> {
    let mut hasher = D::new();
    let mut seeds = Vec::with_capacity(num_of_seeds);
    for i in 0..num_of_seeds {
        hasher.update(salt);
        hasher.update(i.to_le_bytes());
        hasher.update(seed);
        seeds.push(<[u8; 32]>::try_from(hasher.finalize_reset().as_slice()).unwrap());
    }
    seeds
}

#[test]
fn test_hash_chain() {
    let mut hash_chain_output = [0; 32];
    hash_chain::<Blake3>(
        b"01234567890123456789012345678901",
        3,
        &mut hash_chain_output,
    );
    assert_eq!(
        hex::encode(hash_chain_output),
        "9dce6dd3c7e70a6e5052fe1626b97d5ff50f59764513950df43faf76f15efc5c"
    );
}
