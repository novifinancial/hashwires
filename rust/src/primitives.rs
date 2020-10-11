use digest::Digest;
use blake3::Hasher as Blake3;
use std::collections::HashSet;

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

/// Find denominating partition of a numeric `value` in some input `base`.
/// This currently works for u32 only.
pub fn find_dp(value: u32, base: u32) -> Vec<u32> {
    let mut exp: u32 = base;
    let mut ret: Vec<u32> = Vec::new();
    let mut set = HashSet::new();

    set.insert(value);
    while exp < value {
        let mut prev = value;

        // optimizing out the unneeded values. Notice this still needs optimization to avoid
        // duplicated values. Maybe I could just use a set instead of an Vec?
        if (prev + 1) % exp != 0 {
            //  (x//b^i - 1) * b^i + (b-1)
            prev = (prev / exp - 1) * exp + (exp - 1);
            set.insert(prev);
        }
        exp = exp * base;
    }
    for x in set.iter() {
        ret.push(*x);
    }
    ret.sort();
    ret.reverse();
    ret
}

#[test]
fn test_hash_chain() {
    let mut hash_chain_output = [0; 32];
    hash_chain::<Blake3>(b"01234567890123456789012345678901", 3, &mut hash_chain_output);
    assert_eq!(hex::encode(hash_chain_output),
               "9dce6dd3c7e70a6e5052fe1626b97d5ff50f59764513950df43faf76f15efc5c");
}