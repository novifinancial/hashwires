use crate::dp::{find_dp_u32, find_mdp, value_split_per_base};
use crate::hashes::{compute_hash_chains, full_hash_chain, generate_subseeds};
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
    let _hashchain_seeds = generate_subseeds::<Blake3>(&[1u8; 32], seed, num_of_chains);

    // TODO compute hashchains
}

pub fn commit_gen(max_digits: u32, base: u32, value: &BigUint, seed: &[u8]) {
    let bitlength: usize = match base {
        2 => 1,
        4 => 2,
        16 => 4,
        256 => 8,
        _ => panic!(),
    };

    // Step 1: find mdp
    let mdp: Vec<BigUint> = find_mdp(value, base);
    let mdp_len = mdp.len();

    // Step 2: split mdp values per base (bitlength digits)
    let splits: Vec<Vec<u8>> = mdp
        .iter()
        .map(|v| value_split_per_base(v, bitlength))
        .collect();

    // Step 3: compute required hash chains
    let chains: Vec<Vec<[u8; 32]>> =
        compute_hash_chains::<Blake3>(&seed, splits[0].len(), base, splits[0][0]);

    // Step 4: wiring
    let wires: Vec<Vec<[u8; 32]>> = wires(&splits, &chains);
}

fn wires(splits: &Vec<Vec<u8>>, chains: &Vec<Vec<[u8; 32]>>) -> Vec<Vec<[u8; 32]>> {
    splits
        .iter()
        .map(|v| {
            v.iter()
                .enumerate()
                .map(|(i, s)| chains[i][*s as usize])
                .collect()
        })
        .collect()
}

#[test]
fn test_hashwires() {
    let max_digits = 12;
    let base = 10;
    let value = BigUint::from_str_radix("212", 4).unwrap();
    let seed = [0u8; 32];
    commit_gen(10, 4, &value, &seed);
}
