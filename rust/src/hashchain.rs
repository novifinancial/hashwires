use blake3::Hasher as Blake3;
use digest::Digest;

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
