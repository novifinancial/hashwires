use crate::dp::{find_dp_u32, find_mdp, value_split_per_base};
use crate::hashes::{compute_hash_chains, full_hash_chain, generate_subseeds};
use crate::padding::num_base_digits;
use blake3::Hasher as Blake3;
use num_bigint::BigUint;
use num_traits::Num;

use smt::index::TreeIndex;
use smt::node_template::HashNodeSMT;
use smt::traits::{Mergeable, Paddable, ProofExtractable};
use smt::{
    node_template,
    proof::{MerkleProof, RandomSamplingProof},
    traits::{InclusionProvable, RandomSampleable},
    tree::SparseMerkleTree,
};

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

pub fn commit_gen(
    value: &BigUint,
    base: u32,
    seed: &[u8],
    max_number_bits: usize,
    tree_height: usize,
) {
    let bitlength: usize = match base {
        2 => 1,
        4 => 2,
        16 => 4,
        256 => 8,
        _ => panic!(),
    };

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
    let mdp_smt_roots = mdp_smt_roots(&wires, tree_height);

    let x = 6;
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
    commit_gen(&value, 4, &seed, 32, 4);
}
