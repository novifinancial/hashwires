use blake3::Hasher as Blake3;
use digest::Digest;
use std::convert::TryFrom;

pub const LEAF_SALT: &[u8; 32] = b"01234567890123456789012345678901";
pub const TOP_SALT: &[u8; 32] = b"11234567890123456789012345678901";

/// Computes a hash chain using a seed and number of iterations.
#[inline]
#[allow(dead_code)]
pub fn hash_chain<D: Digest>(seed: &[u8], iterations: usize, output: &mut [u8]) {
    // TODO: reuse hashers in single threaded applications, i.e. via finalize_reset()
    let mut hasher = D::new();
    output.copy_from_slice(seed);
    for _i in 0..iterations {
        hasher.update(&output);
        output.copy_from_slice(hasher.finalize_reset().as_slice());
    }
}

/// Return all of the elements of the hash chain, where seed is at index = 0.
#[inline]
#[allow(dead_code)]
pub fn full_hash_chain<D: Digest>(seed: &[u8], size: usize) -> Vec<[u8; 32]> {
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

pub fn compute_hash_chains<D: Digest>(
    seed: &[u8],
    size: usize,
    base: u32,
    most_significant_digit: u8,
) -> Vec<Vec<[u8; 32]>> {
    let mut output: Vec<Vec<[u8; 32]>> = Vec::with_capacity(size);
    let seeds = generate_subseeds::<Blake3>(&LEAF_SALT, seed, size);

    // optimization: first chain might be shorter (up to most_significant_digit in selected base)
    let first_chain = full_hash_chain::<Blake3>(&seeds[0], most_significant_digit as usize + 1);
    output.push(first_chain);

    for i in 1..seeds.len() {
        output.push(full_hash_chain::<Blake3>(&seeds[i], base as usize));
    }
    output
}

/// Simple KDF hash(salt, i, seed)
/// TODO: make it more generic to work for any seed size
#[inline]
#[allow(dead_code)]
pub fn salted_hash<D: Digest>(salt: &[u8], seed: &[u8]) -> [u8; 32] {
    let mut hasher = D::new();
    hasher.update(salt);
    hasher.update(seed);
    let mut output = [0; 32];
    output.copy_from_slice(hasher.finalize().as_slice());
    output
}

#[inline]
#[allow(dead_code)]
pub fn generate_subseeds<D: Digest>(
    salt: &[u8; 32],
    seed: &[u8],
    num_of_seeds: usize,
) -> Vec<[u8; 32]> {
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
    use blake3::Hasher as Blake3;

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
    assert_eq!(chains[0].len(), 2);
    assert_eq!(chains[1].len(), 3);
    assert_eq!(chains[2].len(), 3);
}
