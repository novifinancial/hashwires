use std::convert::TryFrom;

use blake3::Hasher as Blake3;
use digest::Digest;
use num_bigint::BigUint;

use smt::index::TreeIndex;
use smt::node_template::HashNodeSMT;
use smt::traits::Serializable;
use smt::utils::set_pos_best;
use smt::{node_template, proof::MerkleProof, traits::InclusionProvable, tree::SparseMerkleTree};

use crate::dp::{find_mdp, value_split_per_base};
use crate::errors::HWError;
use crate::hashes::{
    compute_hash_chains, generate_subseeds_16bytes, hash_chain, plr_accumulator, salted_hash,
    TOP_SALT,
};
use crate::shuffle::deterministic_index_shuffling;

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

#[allow(clippy::type_complexity)]
pub fn bigger_than_proof_gen<D: Digest>(
    proving_value: &BigUint,
    value: &BigUint,
    base: u32,
    seed: &[u8],
    max_number_bits: usize,
    mdp_smt_height: usize,
) -> Result<(Vec<u8>, Option<[u8; 32]>, Vec<[u8; 32]>, [u8; 16], Vec<u8>), HWError> {
    // Step 0: compute base's bitlength
    let bitlength = compute_bitlength(base);

    // Step 1: find MDP
    let mdp: Vec<BigUint> = find_mdp(value, base);

    // Step 2: split MDP values per base (bitlength digits)
    let splits: Vec<Vec<u8>> = mdp_splits(&mdp, bitlength);

    // Step 3: compute required hashchains
    let chains: Vec<Vec<[u8; 32]>> =
        compute_hash_chains::<D>(&seed, splits[0].len(), base, splits[0][0]);

    // Step 4: MDP to hashchain(s) position wiring
    let wires: Vec<Vec<[u8; 32]>> = wires(&splits, &chains);

    // Step A: pick mdp index
    // TODO remove unwrap()
    let mdp_index = pick_mdp_index(proving_value, &mdp).unwrap();

    // Step B: split proving value per base (bitlength digits)
    let proving_value_split = value_split_per_base(proving_value, bitlength);

    // Step 5: PLR roots per MDP
    let (plr_roots, plr_proof) = plr_roots_and_proof::<D>(
        seed,
        &wires,
        max_number_bits / bitlength,
        mdp_index,
        proving_value_split.len(),
    );

    // Step 6: compute top salts
    let salts = generate_subseeds_16bytes::<D>(TOP_SALT, seed, plr_roots.len());

    // Step 7: KDF smt roots
    let top_salted_roots: Vec<[u8; 32]> = plr_roots
        .iter()
        .enumerate()
        .map(|(i, v)| salted_hash::<D>(&salts[i], v))
        .collect();

    // Step 8: get shuffled indexes
    let shuffled_indexes = deterministic_index_shuffling(
        top_salted_roots.len(),
        max_number_bits / bitlength,
        <[u8; 32]>::try_from(seed).unwrap(),
    );

    // Step 9: Compute final root (HW commitment)
    let hw_commitment = final_smt_root_and_proof::<D>(
        &top_salted_roots,
        &shuffled_indexes?,
        mdp_smt_height,
        mdp_index,
    );

    // Step C: pick hashchain nodes for the proving value
    let chain_nodes = proving_value_chain_nodes(&chains, &splits, &proving_value_split, mdp_index);

    Ok((
        hw_commitment.0,
        plr_proof,
        chain_nodes,
        salts[mdp_index],
        hw_commitment.1,
    ))
}

pub fn proof_verify<D: Digest>(
    proving_value: &BigUint,
    base: u32,
    commitment: &[u8],
    plr_padding: &Option<[u8; 32]>,
    chain_nodes: &[[u8; 32]],
    mdp_salt: &[u8; 16],
    smt_inclusion_proof: &[u8],
) -> bool {
    let bitlength = compute_bitlength(base);
    let requested_value_split = value_split_per_base(proving_value, bitlength);
    let mdp_chain_nodes: Vec<[u8; 32]> = chain_nodes
        .iter()
        .enumerate()
        .map(|(i, v)| hash_chain::<D>(v, requested_value_split[i] as usize))
        .collect();

    let mut hasher = D::new();

    match plr_padding {
        Some(p) => {
            hasher.update(&p);
        }
        None => {}
    }

    let mut mdp_root = [0; 32];
    mdp_chain_nodes.iter().enumerate().for_each(|(i, v)| {
        if i != 0 {
            hasher.update(&mdp_root);
        }
        hasher.update(v);
        mdp_root.copy_from_slice(hasher.finalize_reset().as_slice());
    });

    let salted_mdp_root = salted_hash::<D>(mdp_salt, &mdp_root);

    // Decode the Merkle proof.
    let deserialized_proof =
        MerkleProof::<HashNodeSMT<Blake3>>::deserialize(&smt_inclusion_proof).unwrap();

    let commitment_node = HashNodeSMT::<Blake3>::new(commitment.to_owned());
    let smt_mdp_node = HashNodeSMT::<Blake3>::new(salted_mdp_root.to_vec());

    deserialized_proof.verify_inclusion_proof(&[smt_mdp_node], &commitment_node)
}

pub fn commit_gen<D: Digest>(
    value: &BigUint,
    base: u32,
    seed: &[u8],
    max_number_bits: usize,
    mdp_smt_height: usize,
) -> Result<Vec<u8>, HWError> {
    // Step 0: compute base's bitlength
    let bitlength = compute_bitlength(base);

    // Step 1: find MDP
    let mdp: Vec<BigUint> = find_mdp(value, base);

    // Step 2: split MDP values per base (bitlength digits)
    let splits: Vec<Vec<u8>> = mdp_splits(&mdp, bitlength);

    // Step 3: compute required hash chains
    let chains: Vec<Vec<[u8; 32]>> =
        compute_hash_chains::<D>(&seed, splits[0].len(), base, splits[0][0]);

    // Step 4: MDP to hashchain(s) position wiring
    let wires: Vec<Vec<[u8; 32]>> = wires(&splits, &chains);

    // Step 5: SMT roots per MDP
    let plr_roots = plr_roots::<D>(seed, &wires, max_number_bits / bitlength);

    // Step 6: compute top salts
    let salts = generate_subseeds_16bytes::<D>(TOP_SALT, seed, plr_roots.len());

    // Step 7: KDF smt roots
    let top_salted_roots: Vec<[u8; 32]> = plr_roots
        .iter()
        .enumerate()
        .map(|(i, v)| salted_hash::<D>(&salts[i], v))
        .collect();

    // Step 8: get shuffled indexes
    let shuffled_indexes = deterministic_index_shuffling(
        top_salted_roots.len(),
        max_number_bits / bitlength,
        <[u8; 32]>::try_from(seed).unwrap(),
    );

    // Step 9: Compute final root (HW commitment)
    let hw_commitment = final_smt_root::<D>(&top_salted_roots, &shuffled_indexes?, mdp_smt_height);
    Ok(hw_commitment)
}

/// Get required chain nodes for proofs
fn proving_value_chain_nodes(
    chains: &[Vec<[u8; 32]>],
    mdp_splits: &[Vec<u8>],
    proving_value_split: &[u8],
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
fn pick_mdp_index(proving_value: &BigUint, mdp: &[BigUint]) -> Result<usize, &'static str> {
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

fn final_smt_root<D: Digest>(
    top_salted_roots: &[[u8; 32]],
    shuffled_indexes: &[usize],
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

fn final_smt_root_and_proof<D: Digest>(
    top_salted_roots: &[[u8; 32]],
    shuffled_indexes: &[usize],
    tree_height: usize,
    leaf_index: usize,
) -> (Vec<u8>, Vec<u8>) {
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

    let node = smt_leaves[leaf_index].0;

    smt_leaves.sort_by(|(t1, _), (t2, _)| t1.cmp(t2));
    let mut tree: SMT<node_template::HashNodeSMT<Blake3>> = SMT::new(tree_height);
    tree.build(&smt_leaves);

    let inclusion_proof =
        MerkleProof::<node_template::HashNodeSMT<Blake3>>::generate_inclusion_proof(&tree, &[node])
            .unwrap();
    let smt_proof = inclusion_proof.serialize();

    (tree.get_root_raw().serialize(), smt_proof)
}

fn mdp_splits(mdp: &[BigUint], bitlength: usize) -> Vec<Vec<u8>> {
    mdp.iter()
        .map(|v| value_split_per_base(v, bitlength))
        .collect()
}

fn plr_roots_and_proof<D: Digest>(
    seed: &[u8],
    wires: &[Vec<[u8; 32]>],
    max_length: usize,
    mdp_index: usize,
    proving_value_split_size: usize,
) -> (Vec<[u8; 32]>, Option<[u8; 32]>) {
    let plr: Vec<([u8; 32], Option<[u8; 32]>)> = wires
        .iter()
        .map(|v| plr_accumulator::<D>(seed, v, max_length, proving_value_split_size))
        .collect();

    (plr.iter().map(|v| (*v).0).collect(), plr[mdp_index].1)
}

fn plr_roots<D: Digest>(seed: &[u8], wires: &[Vec<[u8; 32]>], max_length: usize) -> Vec<[u8; 32]> {
    wires
        .iter()
        .map(|v| plr_accumulator::<D>(seed, v, max_length, v.len()).0)
        .collect()
}

fn wires(splits: &[Vec<u8>], chains: &[Vec<[u8; 32]>]) -> Vec<Vec<[u8; 32]>> {
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

#[cfg(test)]
mod tests {
    use num_traits::Num;

    use smt::utils::print_output;

    use super::*;

    #[test]
    fn test_hashwires() {
        let max_digits = 32;
        let base = 4;
        let mdp_tree_height = 4;
        let value = BigUint::from_str_radix("212", 4).unwrap();
        let seed = [0u8; 32];
        let proving_value = BigUint::from_str_radix("201", 4).unwrap();
        let hw_commit_and_proof = bigger_than_proof_gen::<Blake3>(
            &proving_value,
            &value,
            base,
            &seed,
            max_digits,
            mdp_tree_height,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&hw_commit_and_proof.0),
            "b3cbed18644291b4cc300c265609432dc9797d29e4123bd0bf763c9299cbdc6f"
        );
        assert!(proof_verify::<Blake3>(
            &proving_value,
            base,
            &hw_commit_and_proof.0,
            &hw_commit_and_proof.1,
            &hw_commit_and_proof.2,
            &hw_commit_and_proof.3,
            &hw_commit_and_proof.4,
        ));

        let max_digits = 32;
        let base = 16;
        let mdp_tree_height = 3;
        let value = BigUint::from_str_radix("1AB", 16).unwrap();
        let seed = [0u8; 32];
        let hw_commit =
            commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height).unwrap();
        assert_eq!(
            hex::encode(hw_commit),
            "1c9faca8f6159f8e5041bebd823de9e3c252f25a8071543ee6c3a4c1c974d411"
        );

        let max_digits = 64;
        let base = 256;
        let mdp_tree_height = 3;
        let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
        let seed = [0u8; 32];
        let hw_commit =
            commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height).unwrap();
        assert_eq!(
            hex::encode(hw_commit),
            "2647d6e7aaa0c752f4adb7cff9274cb7f4f6a7952002741b85628dc8ac06a81e"
        );

        let max_digits = 128;
        let base = 256;
        let mdp_tree_height = 4;
        let value = BigUint::from_str_radix("23479534957845324957342523490585324", 10).unwrap();
        let seed = [0u8; 32];
        let hw_commit =
            commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height).unwrap();
        assert_eq!(
            hex::encode(hw_commit),
            "84dd666be754f4bbe7a344d8b6dc8f0fa3c708dd5dbd45904301b84ba2ec37ff"
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
}
