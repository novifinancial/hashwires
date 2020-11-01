use crate::dp::find_dp_u32;
use crate::hashes::generate_subseeds;
use crate::padding::num_base_digits;
use blake3::Hasher as Blake3;
use num_bigint::BigUint;
use num_traits::Num;

/// Function to generate HW commitments
#[allow(dead_code)]
pub fn generate_commitment(max_digits: u32, base: u32, value_base10_string: &str, seed: &[u8]) {
    // num to BigInt
    let value_bigint = BigUint::from_str_radix(value_base10_string, 10).unwrap();

    // vector of DP
    let _dp = find_dp_u32(&value_bigint.to_str_radix(base), base);

    // number of digits on input base (which is equal to the num of chains required)
    let num_of_chains = num_base_digits(max_digits, base, &value_bigint);

    // compute hashchain seeds
    let _hashchain_seeds = generate_subseeds::<Blake3>(b"hashchain_salt", seed, num_of_chains);
}

#[test]
fn test_hashwires() {
    let max_digits = 12;
    let base = 10;
    let value_base10 = "3413";
    let seed = [0u8; 32];
    generate_commitment(max_digits, base, value_base10, &seed);
}
