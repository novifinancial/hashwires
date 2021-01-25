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
use smt::utils::{print_output, set_pos_best};
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

pub fn bigger_than_proof_gen(
    proving_value: &BigUint,
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

    // Step 3: compute required hashchains
    let chains: Vec<Vec<[u8; 32]>> =
        compute_hash_chains::<Blake3>(&seed, splits[0].len(), base, splits[0][0]);

    // Step 4: MDP to hashchain(s) position wiring
    let wires: Vec<Vec<[u8; 32]>> = wires(&splits, &chains);

    // Step A: pick mdp index
    // TODO remove unwrap()
    let mdp_index = pick_mdp_index(proving_value, &mdp).unwrap();

    // Step B: split proving value per base (bitlength digits)
    let proving_value_split = value_split_per_base(proving_value, bitlength);

    // Step 5: SMT roots per MDP
    let mdp_smt_roots = mdp_smt_roots(&wires, mdp_smt_height);
    mdp_smt_roots_and_proof(&wires, mdp_smt_height, mdp_index, proving_value_split.len());

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

    // ---- Proof generation ----
    // Step A: pick mdp index
    // TODO remove unwrap()
    let mdp_index = pick_mdp_index(proving_value, &mdp).unwrap();

    // Step B: split proving value per base (bitlength digits)
    let proving_value_split = value_split_per_base(proving_value, bitlength);

    // Step C: pick hachchain nodes for the proving value
    let chain_nodes = proving_value_chain_nodes(&chains, &splits, &proving_value_split, mdp_index);

    // Step D: MDP chains SMT composite proof
    // let mdp_chain_smt_proof =

    hw_commitment
}

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

/// Get required chain nodes for proofs
fn proving_value_chain_nodes(
    chains: &Vec<Vec<[u8; 32]>>,
    mdp_splits: &Vec<Vec<u8>>,
    proving_value_split: &Vec<u8>,
    mdp_index: usize,
) -> Vec<[u8; 32]> {
    proving_value_split
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let chain_index = i + chains.len() - proving_value_split.len();
            let mdp_split_index = i + mdp_splits[mdp_index].len() - proving_value_split.len();
            chains[chain_index][(mdp_splits[mdp_index][mdp_split_index] - *s) as usize]
        })
        .collect()
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
    let mut smt_leaves: Vec<(TreeIndex, node_template::HashNodeSMT<Blake3>)> = top_salted_roots
        .iter()
        .enumerate()
        .map(|(i, s)| {
            (
                set_pos_best(tree_height, shuffled_indexes[i] as u32),
                node_template::HashNodeSMT::<Blake3>::new(s.to_vec()),
            )
        })
        .collect();

    smt_leaves.sort_by(|(t1, _), (t2, _)| t1.cmp(t2));
    let mut tree: SMT<node_template::HashNodeSMT<Blake3>> = SMT::new(tree_height);
    tree.build(&smt_leaves);
    tree.get_root_raw().serialize()
}

fn mdp_splits(mdp: &Vec<BigUint>, bitlength: usize) -> Vec<Vec<u8>> {
    mdp.iter()
        .map(|v| value_split_per_base(v, bitlength))
        .collect()
}

fn mdp_smt_roots_and_proof(
    wires: &Vec<Vec<[u8; 32]>>,
    tree_height: usize,
    mdp_index: usize,
    proving_value_split_size: usize,
) -> (
    Vec<smt::node_template::HashNodeSMT<blake3::Hasher>>,
    Vec<u8>,
) {
    let smt_leaves: Vec<Vec<(TreeIndex, node_template::HashNodeSMT<Blake3>)>> = wires
        .iter()
        .map(|v| {
            v.iter()
                .enumerate()
                .map(|(i, s)| {
                    (
                        set_pos_best(tree_height, i as u32),
                        node_template::HashNodeSMT::<Blake3>::new(s.to_vec()),
                    )
                })
                .collect()
        })
        .collect();

    let mut smt_roots = Vec::with_capacity(smt_leaves.len());
    let mut proof: Vec<u8> = Vec::new();
    smt_leaves.iter().enumerate().for_each(|(i, v)| {
        let mut tree: SMT<node_template::HashNodeSMT<Blake3>> = SMT::new(tree_height);
        tree.build(v);
        smt_roots.push(tree.get_root_raw().clone());
        if i == mdp_index {
            let mut inclusion_list = vec![];
            &v[v.len() - proving_value_split_size..v.len()]
                .iter()
                .for_each(|(t, v)| {
                    inclusion_list.push(*t);
                });
        }
    });
    (smt_roots, proof)
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
                        set_pos_best(tree_height, i as u32),
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
    let proving_value = BigUint::from_str_radix("201", 4).unwrap();
    let hw_commit = bigger_than_proof_gen(
        &proving_value,
        &value,
        base,
        &seed,
        max_digits,
        mdp_tree_height,
    );
    assert_eq!(
        hex::encode(hw_commit),
        "7dda9ebf56c447b6fc5b25cee32f8e1b338fc8df383cbbd3b2da3bcee70893de"
    );

    let max_digits = 32;
    let base = 16;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1AB", 16).unwrap();
    let seed = [0u8; 32];
    let hw_commit = commit_gen(&value, base, &seed, max_digits, mdp_tree_height);
    assert_eq!(
        hex::encode(hw_commit),
        "e993b4b34c2541815ce9d945f7cf12aa20db421b9f7558e84e25e18bd8692051"
    );

    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];
    let hw_commit = commit_gen(&value, base, &seed, max_digits, mdp_tree_height);
    assert_eq!(
        hex::encode(hw_commit),
        "5dbb0f45d044086bb149c6b5aa52b526a91f9d4761d727dfabcef0eb9ebfa5cd"
    );

    let max_digits = 128;
    let base = 256;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("23479534957845324957342523490585324", 10).unwrap();
    let seed = [0u8; 32];
    let hw_commit = commit_gen(&value, base, &seed, max_digits, mdp_tree_height);
    assert_eq!(
        hex::encode(hw_commit),
        "cec8e4a8abd98c984a91a37171310650861aa99b68e0011f7f73fd406d806fd6"
    );
}

#[test]
fn testsmt() {
    let tree_height = 4;
    let mut tree: SMT<node_template::HashNodeSMT<Blake3>> = SMT::new(tree_height);
    let mut v = vec![];
    let a = (
        set_pos_best(tree_height, 0),
        node_template::HashNodeSMT::<Blake3>::new(vec![1; 32]),
    );
    let b = (
        set_pos_best(tree_height, 1),
        node_template::HashNodeSMT::<Blake3>::new(vec![2; 32]),
    );
    let c = (
        set_pos_best(tree_height, 15),
        node_template::HashNodeSMT::<Blake3>::new(vec![3; 32]),
    );
    v.push(a);
    v.push(b);
    v.push(c);
    tree.build(&v);
    println!("{}", tree.get_leaves().len());
    print_output(&tree);
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
