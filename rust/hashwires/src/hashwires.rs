use crate::dp::{find_dp_u32, find_mdp, value_split_per_base};
use crate::hashes::{
    compute_hash_chains, full_hash_chain, generate_subseeds, salted_hash, TOP_SALT,
};
use crate::padding::num_base_digits;
use blake3::Hasher as Blake3;
use num_bigint::BigUint;
use num_traits::Num;

use crate::shuffle::deterministic_index_shuffling;
use digest::Digest;
use smt::index::TreeIndex;
use smt::node_template::HashNodeSMT;
use smt::traits::{Mergeable, Paddable, ProofExtractable, Serializable};
use smt::{
    node_template,
    proof::{MerkleProof, RandomSamplingProof},
    traits::{InclusionProvable, RandomSampleable},
    tree::SparseMerkleTree,
};
use std::convert::TryFrom;
use std::fmt::Error;

type SMT<P> = SparseMerkleTree<P>;

// /// Function to generate HW commitments
// #[allow(dead_code)]
// pub fn generate_commitment(max_digits: u32, base: u32, value_base10_string: &str, seed: &[u8]) {
//     // num to BigInt
//     let value_bigint = BigUint::from_str_radix(value_base10_string, 10).unwrap();
//
//     // vector of DP
//     let _dp = find_dp_u32(&value_bigint.to_str_radix(base), base);
//
//     // number of digits on input base (which is equal to the num of chains required)
//     let num_of_chains = num_base_digits(max_digits, base, &value_bigint);
//
//     // compute hashchain seeds
//     let _hashchain_seeds = generate_subseeds::<Blake3>(&[1u8; 32], seed, num_of_chains);
//
//     // TODO compute hashchains
// }

// pub fn bigger_than_proof_gen(
//     proving_value: &BigUint,
//     value: &BigUint,
//     base: u32,
//     seed: &[u8],
//     max_number_bits: usize,
//     mdp_smt_height: usize,
// ) -> Vec<u8> {
//     // Step 0: compute base's bitlength
//     let bitlength = compute_bitlength(base);
//
//     // Step 1: find MDP
//     let mdp: Vec<BigUint> = find_mdp(value, base);
//
//     // Step A: pick mdp index
//     let mdp_index = pick_mdp_index(proving_value, &mdp);
//
//     // Step 2: split MDP values per base (bitlength digits)
//     let splits: Vec<Vec<u8>> = mdp_splits(&mdp, bitlength);
//
//     // Step 3: compute required hash chains
//     let chains: Vec<Vec<[u8; 32]>> =
//         compute_hash_chains::<Blake3>(&seed, splits[0].len(), base, splits[0][0]);
//
//     // Step 4: MDP to hashchain(s) position wiring
//     let wires: Vec<Vec<[u8; 32]>> = wires(&splits, &chains);
//
//     // Step 5: SMT roots per MDP
//     let mdp_smt_roots = mdp_smt_roots(&wires, mdp_smt_height);
//
//     // Step 6: compute top salts
//     let salts = generate_subseeds::<Blake3>(TOP_SALT, seed, mdp_smt_roots.len());
//
//     // Step 7: KDF smt roots
//     let top_salted_roots: Vec<[u8; 32]> = mdp_smt_roots
//         .iter()
//         .enumerate()
//         .map(|(i, v)| salted_hash::<Blake3>(&salts[i], &v.serialize()))
//         .collect();
//
//     // Step 8: get shuffled indexes
//     let shuffled_indexes = deterministic_index_shuffling(
//         top_salted_roots.len(),
//         max_number_bits / bitlength,
//         <[u8; 32]>::try_from(seed).unwrap(),
//     );
//
//     // Step 9: Compute final root (HW commitment)
//     let hw_commitment = final_smt_root(&top_salted_roots, &shuffled_indexes, mdp_smt_height);
//     hw_commitment
// }

pub fn commit_gen(
    value: &BigUint,
    base: u32,
    seed: &[u8],
    max_number_bits: usize,
    mdp_smt_height: usize,
) -> Vec<u8> {
    // Step 0: compute base's bitlength
    let bitlength = compute_bitlength(base);

    // Step 1: find MDP
    let mdp: Vec<BigUint> = find_mdp(value, base);

    // Step 2: split MDP values per base (bitlength digits)
    let splits: Vec<Vec<u8>> = mdp_splits(&mdp, bitlength);

    // Step 3: compute required hash chains
    let chains: Vec<Vec<[u8; 32]>> =
        compute_hash_chains::<Blake3>(&seed, splits[0].len(), base, splits[0][0]);

    // Step 4: MDP to hashchain(s) position wiring
    let wires: Vec<Vec<[u8; 32]>> = wires(&splits, &chains);

    // Step 5: SMT roots per MDP
    let mdp_smt_roots = mdp_smt_roots(&wires, mdp_smt_height);

    // Step 6: compute top salts
    let salts = generate_subseeds::<Blake3>(TOP_SALT, seed, mdp_smt_roots.len());

    // Step 7: KDF smt roots
    let top_salted_roots: Vec<[u8; 32]> = mdp_smt_roots
        .iter()
        .enumerate()
        .map(|(i, v)| salted_hash::<Blake3>(&salts[i], &v.serialize()))
        .collect();

    // Step 8: get shuffled indexes
    let shuffled_indexes = deterministic_index_shuffling(
        top_salted_roots.len(),
        max_number_bits / bitlength,
        <[u8; 32]>::try_from(seed).unwrap(),
    );

    // Step 9: Compute final root (HW commitment)
    let hw_commitment = final_smt_root(&top_salted_roots, &shuffled_indexes, mdp_smt_height);
    hw_commitment
}

/// find the mdp index where proving_value <= mdp[i]
/// TODO: use binary search
fn pick_mdp_index(proving_value: &BigUint, mdp: &Vec<BigUint>) -> Result<usize, &'static str> {
    for i in (0..mdp.len()).rev() {
        if proving_value <= &mdp[i] {
            return Ok(i);
        }
    }
    Err("Proving value is bigger than the issued value")
}

/// Compute base's bitlength.
fn compute_bitlength(base: u32) -> usize {
    match base {
        2 => 1,
        4 => 2,
        16 => 4,
        256 => 8,
        _ => panic!(),
    }
}

fn final_smt_root(
    top_salted_roots: &Vec<[u8; 32]>,
    shuffled_indexes: &Vec<usize>,
    tree_height: usize,
) -> Vec<u8> {
    let smt_leaves: Vec<(TreeIndex, node_template::HashNodeSMT<Blake3>)> = top_salted_roots
        .iter()
        .enumerate()
        .map(|(i, s)| {
            (
                TreeIndex::new(tree_height, index_to_256bits(shuffled_indexes[i])),
                node_template::HashNodeSMT::<Blake3>::new(s.to_vec()),
            )
        })
        .collect();

    let mut tree: SMT<node_template::HashNodeSMT<Blake3>> = SMT::new(tree_height);
    tree.build(&smt_leaves);
    tree.get_root_raw().serialize()
}

fn mdp_splits(mdp: &Vec<BigUint>, bitlength: usize) -> Vec<Vec<u8>> {
    mdp.iter()
        .map(|v| value_split_per_base(v, bitlength))
        .collect()
}

fn mdp_smt_roots(
    wires: &Vec<Vec<[u8; 32]>>,
    tree_height: usize,
) -> Vec<smt::node_template::HashNodeSMT<blake3::Hasher>> {
    let smt_leaves: Vec<Vec<(TreeIndex, node_template::HashNodeSMT<Blake3>)>> = wires
        .iter()
        .map(|v| {
            v.iter()
                .enumerate()
                .map(|(i, s)| {
                    (
                        TreeIndex::new(tree_height, index_to_256bits(i)),
                        node_template::HashNodeSMT::<Blake3>::new(s.to_vec()),
                    )
                })
                .collect()
        })
        .collect();

    let mut smt_roots = Vec::with_capacity(smt_leaves.len());
    smt_leaves.iter().for_each(|v| {
        let mut tree: SMT<node_template::HashNodeSMT<Blake3>> = SMT::new(tree_height);
        tree.build(v);
        smt_roots.push(tree.get_root_raw().clone());
    });
    smt_roots
}

// TODO: this a PoC temporary untested (probably wrong) impl.
fn index_to_256bits(i: usize) -> [u8; 32] {
    let mut output = [0u8; 32];
    output[0] = reverse_order_of_byte(i.to_le_bytes()[0]);
    output
}

// TODO there exist faster approaches, ie via look up tables.
fn reverse_order_of_byte(mut b: u8) -> u8 {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    b
}

fn wires(splits: &Vec<Vec<u8>>, chains: &Vec<Vec<[u8; 32]>>) -> Vec<Vec<[u8; 32]>> {
    splits
        .iter()
        .map(|v| {
            v.iter()
                .enumerate()
                .map(|(i, s)| {
                    let mut index = i;
                    if v.len() < chains.len() {
                        index += 1;
                    }
                    chains[index][*s as usize]
                })
                .collect()
        })
        .collect()
}

#[test]
fn test_hashwires() {
    let max_digits = 32;
    let base = 4;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("212", 4).unwrap();
    let seed = [0u8; 32];
    let hw_commit = commit_gen(&value, base, &seed, max_digits, mdp_tree_height);
    assert_eq!(
        hex::encode(hw_commit),
        "7428334c5ab6190f0aea09543ad95458e9ead2b977737b0272bd335e4474eac8"
    );

    let max_digits = 32;
    let base = 16;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1AB", 16).unwrap();
    let seed = [0u8; 32];
    let hw_commit = commit_gen(&value, base, &seed, max_digits, mdp_tree_height);
    assert_eq!(
        hex::encode(hw_commit),
        "47548b6847b91cdeeebe3a47ffd8106eb043f3853934311d842dbcb1888573af"
    );

    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];
    let hw_commit = commit_gen(&value, base, &seed, max_digits, mdp_tree_height);
    assert_eq!(
        hex::encode(hw_commit),
        "fd9c9d4d5d7a491a19fe9a4e223ffd9302d25acc8a5e2a82fa49131c1c4ffc53"
    );

    let max_digits = 128;
    let base = 256;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("23479534957845324957342523490585324", 10).unwrap();
    let seed = [0u8; 32];
    let hw_commit = commit_gen(&value, base, &seed, max_digits, mdp_tree_height);
    assert_eq!(
        hex::encode(hw_commit),
        "d79266e03efeea066c7cc864553845b2e8f1e271caf6af8a84c1a415cd71305d"
    );
}

#[test]
fn test_pick_mdp_index() {
    let mdp = vec![
        BigUint::from(3143u16),
        BigUint::from(3139u16),
        BigUint::from(3099u16),
        BigUint::from(2999u16),
    ];
    assert_eq!(pick_mdp_index(&BigUint::from(3142u16), &mdp).unwrap(), 0);
    assert_eq!(pick_mdp_index(&BigUint::from(3140u16), &mdp).unwrap(), 0);

    assert_eq!(pick_mdp_index(&BigUint::from(3139u16), &mdp).unwrap(), 1);
    assert_eq!(pick_mdp_index(&BigUint::from(3100u16), &mdp).unwrap(), 1);

    assert_eq!(pick_mdp_index(&BigUint::from(3099u16), &mdp).unwrap(), 2);
    assert_eq!(pick_mdp_index(&BigUint::from(3000u16), &mdp).unwrap(), 2);

    assert_eq!(pick_mdp_index(&BigUint::from(2999u16), &mdp).unwrap(), 3);
    assert_eq!(pick_mdp_index(&BigUint::from(0u16), &mdp).unwrap(), 3);
}
