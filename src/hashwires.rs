// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::convert::TryFrom;

use digest::Digest;
use generic_array::{
    typenum::{Unsigned, U16, U32},
    GenericArray,
};
use num_bigint::BigUint;

use crate::dp::{find_mdp, value_split_per_base};
use crate::errors::HwError;
use crate::hashes::{
    compute_hash_chains, generate_subseeds, hash_chain, plr_accumulator, salted_hash,
    SMTREE_PADDING_SALT, TOP_SALT,
};
use crate::serialization::{serialize, take_slice, tokenize};
use crate::shuffle::deterministic_index_shuffling;
use crate::traits::Hash;
use smtree::index::TreeIndex;
use smtree::node_template::HashWiresNodeSmt;
use smtree::pad_secret::Secret as SmtSecret;
use smtree::traits::Serializable;
use smtree::{
    node_template, proof::MerkleProof, traits::InclusionProvable, tree::SparseMerkleTree,
};
use std::marker::PhantomData;

type Smt<P> = SparseMerkleTree<P>;

pub(crate) type PlrPaddingSize = U32;
pub(crate) type ChainNodesSize = U32;
pub(crate) type MdpSaltSize = U16;
pub(crate) type SmtSecretSize = U32;

/// HashWires commitment structure.
pub struct Commitment<D: Hash> {
    base: u32,
    commitment: Vec<u8>,
    _d: PhantomData<D>,
}

/// HashWires secret (value, seed) tuple.
pub struct Secret<D: Hash> {
    value: BigUint,
    seed: Vec<u8>,
    _d: PhantomData<D>,
}

impl<D: Hash> Secret<D> {
    /// Generate a HashWires secret.
    pub fn gen(seed: &[u8], value: &BigUint) -> Self {
        Self {
            value: value.clone(),
            seed: seed.to_vec(),
            _d: PhantomData,
        }
    }

    /// Generate a HashWires commitment.
    pub fn commit(&self, base: u32, max_number_bits: usize) -> Result<Commitment<D>, HwError> {
        let mdp_smt_height = compute_mdp_height(base, max_number_bits);
        let commitment = commit_gen::<D>(
            &self.value,
            base,
            &self.seed,
            max_number_bits,
            mdp_smt_height as usize,
        )?;
        Ok(Commitment {
            base,
            commitment,
            _d: PhantomData,
        })
    }

    /// Generate HashWires proof.
    pub fn prove(
        &self,
        base: u32,
        max_number_bits: usize,
        threshold: &BigUint,
    ) -> Result<Proof, HwError> {
        let mdp_smt_height = compute_mdp_height(base, max_number_bits);
        let result = larger_than_proof_gen::<D>(
            threshold,
            &self.value,
            base,
            &self.seed,
            max_number_bits,
            mdp_smt_height as usize,
        )?;
        Ok(Proof {
            plr_padding: result.1,
            chain_nodes: result.2,
            mdp_salt: result.3,
            smt_inclusion_proof: result.4,
        })
    }
}

impl<D: Hash> Commitment<D> {
    /// Verify a HashWires proof over a commitment.
    pub fn verify(&self, proof: &Proof, threshold: &BigUint) -> Result<(), HwError> {
        let result = proof_verify::<D>(
            threshold,
            self.base,
            &self.commitment,
            &proof.plr_padding,
            &proof.chain_nodes,
            &proof.mdp_salt,
            &proof.smt_inclusion_proof,
        );
        match result? {
            true => Ok(()),
            false => Err(HwError::ProofVerificationError),
        }
    }

    /// Serialize a HashWires commitment.
    pub fn serialize(&self) -> Vec<u8> {
        self.commitment.clone()
    }

    /// Deserialize a HashWires commitment.
    pub fn deserialize(bytes: &[u8], base: u32) -> Self {
        Self {
            base,
            commitment: bytes.to_vec(),
            _d: PhantomData,
        }
    }
}

/// HashWires Proof structure.
pub struct Proof {
    plr_padding: Option<GenericArray<u8, PlrPaddingSize>>,
    chain_nodes: Vec<GenericArray<u8, ChainNodesSize>>,
    mdp_salt: GenericArray<u8, MdpSaltSize>,
    smt_inclusion_proof: Vec<u8>,
}

impl Proof {
    /// Serializing a HashWires proof.
    pub fn serialize(&self) -> Vec<u8> {
        let mut chain_nodes_flattened = vec![];
        for elem in self.chain_nodes.iter() {
            chain_nodes_flattened.extend_from_slice(elem);
        }
        let mut result = [
            &serialize(&chain_nodes_flattened, 2),
            &self.mdp_salt.to_vec()[..],
            &serialize(&self.smt_inclusion_proof, 2),
        ]
        .concat();
        if let Some(v) = &self.plr_padding {
            result.extend_from_slice(&v);
        }

        result
    }

    /// Deserializing a HashWires proof.
    pub fn deserialize(input: &[u8]) -> Result<Self, HwError> {
        let (chain_nodes_flattened, remainder) = tokenize(&input, 2)?;
        let (mdp_salt, remainder) = take_slice(&remainder, MdpSaltSize::to_usize())?;
        let (smt_inclusion_proof, remainder) = tokenize(&remainder, 2)?;
        let plr_padding = match remainder.is_empty() {
            true => None,
            false => {
                let (padding, remainder) = take_slice(&remainder, PlrPaddingSize::to_usize())?;
                if !remainder.is_empty() {
                    return Err(HwError::SerializationError);
                }
                Some(GenericArray::clone_from_slice(&padding))
            }
        };

        let mut chain_nodes = vec![];
        let mut cn_index = 0;
        while cn_index < chain_nodes_flattened.len() {
            chain_nodes.push(GenericArray::clone_from_slice(
                &chain_nodes_flattened[cn_index..cn_index + ChainNodesSize::to_usize()],
            ));
            cn_index += ChainNodesSize::to_usize();
        }
        if cn_index != chain_nodes_flattened.len() {
            return Err(HwError::SerializationError);
        }

        Ok(Self {
            chain_nodes,
            plr_padding,
            mdp_salt: GenericArray::clone_from_slice(&mdp_salt),
            smt_inclusion_proof,
        })
    }
}

/// Generate larger than proof.
#[allow(clippy::type_complexity)]
pub fn larger_than_proof_gen<D: Hash>(
    proving_value: &BigUint,
    value: &BigUint,
    base: u32,
    seed: &[u8],
    max_number_bits: usize,
    mdp_smt_height: usize,
) -> Result<
    (
        Vec<u8>,
        Option<GenericArray<u8, PlrPaddingSize>>,
        Vec<GenericArray<u8, ChainNodesSize>>,
        GenericArray<u8, MdpSaltSize>,
        Vec<u8>,
    ),
    HwError,
> {
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
    let mdp_index = pick_mdp_index(proving_value, &mdp)?;

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
    let salts = generate_subseeds::<D, MdpSaltSize>(TOP_SALT, seed, plr_roots.len());

    // Step 7: KDF smt roots
    let top_salted_roots = compute_plr_roots::<D>(&plr_roots, &salts);

    // Step 8: get shuffled indexes
    let shuffled_indexes = deterministic_index_shuffling(
        top_salted_roots.len(),
        max_number_bits / bitlength,
        <[u8; 32]>::try_from(seed).map_err(|_| HwError::SeedLengthError)?,
    );

    // Step 9: Compute final root (HW commitment)
    let smt_secret = generate_subseeds::<D, SmtSecretSize>(SMTREE_PADDING_SALT, seed, 1);
    let hw_commitment = final_smt_root_and_proof::<D>(
        &top_salted_roots,
        &shuffled_indexes?,
        mdp_smt_height,
        mdp_index,
        &SmtSecret::from_bytes(&smt_secret[0]).unwrap(),
    )?;

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

/// Verify HashWires proof.
pub fn proof_verify<D: Hash>(
    proving_value: &BigUint,
    base: u32,
    commitment: &[u8],
    plr_padding: &Option<GenericArray<u8, PlrPaddingSize>>,
    chain_nodes: &[GenericArray<u8, ChainNodesSize>],
    mdp_salt: &GenericArray<u8, MdpSaltSize>,
    smt_inclusion_proof: &[u8],
) -> Result<bool, HwError> {
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
    let deserialized_proof = MerkleProof::<HashWiresNodeSmt<D>>::deserialize(&smt_inclusion_proof)
        .map_err(|_| HwError::MerkleProofDecodingError)?;

    let commitment_node = HashWiresNodeSmt::<D>::new(commitment.to_owned());
    let smt_mdp_node = HashWiresNodeSmt::<D>::new(salted_mdp_root.to_vec());

    Ok(deserialized_proof.verify_inclusion_proof(&[smt_mdp_node], &commitment_node))
}

/// Generate HashWires commitment.
pub fn commit_gen<D: Hash>(
    value: &BigUint,
    base: u32,
    seed: &[u8],
    max_number_bits: usize,
    mdp_smt_height: usize,
) -> Result<Vec<u8>, HwError> {
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
    let salts = generate_subseeds::<D, MdpSaltSize>(TOP_SALT, seed, plr_roots.len());

    // Step 7: KDF smt roots
    let top_salted_roots = compute_plr_roots::<D>(&plr_roots, &salts);

    // Step 8: get shuffled indexes
    let shuffled_indexes = deterministic_index_shuffling(
        top_salted_roots.len(),
        max_number_bits / bitlength,
        <[u8; 32]>::try_from(seed).map_err(|_| HwError::SeedLengthError)?,
    );

    // Step 9: Compute final root (HW commitment)
    let smt_secret = generate_subseeds::<D, SmtSecretSize>(SMTREE_PADDING_SALT, seed, 1);
    let hw_commitment = final_smt_root::<D>(
        &top_salted_roots,
        &shuffled_indexes?,
        mdp_smt_height,
        &SmtSecret::from_bytes(&smt_secret[0]).unwrap(),
    );
    Ok(hw_commitment)
}

//////////////////////
// Helper functions //
//////////////////////

// Compute plr roots; this function is reused, so we extracted it.
fn compute_plr_roots<D: Hash>(
    plr_roots: &[GenericArray<u8, PlrPaddingSize>],
    salts: &[GenericArray<u8, MdpSaltSize>],
) -> Vec<[u8; 32]> {
    plr_roots
        .iter()
        .enumerate()
        .map(|(i, v)| salted_hash::<D>(&salts[i], v))
        .collect()
}

// Get required chain nodes for proofs
fn proving_value_chain_nodes(
    chains: &[Vec<[u8; 32]>],
    mdp_splits: &[Vec<u8>],
    proving_value_split: &[u8],
    mdp_index: usize,
) -> Vec<GenericArray<u8, ChainNodesSize>> {
    proving_value_split
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let chain_index = i + chains.len() - proving_value_split.len();
            let mdp_split_index = i + mdp_splits[mdp_index].len() - proving_value_split.len();
            let result =
                chains[chain_index][(mdp_splits[mdp_index][mdp_split_index] - *s) as usize];
            GenericArray::clone_from_slice(&result[..])
        })
        .collect()
}

// find the mdp index where proving_value <= mdp[i]
// TODO: use binary search
fn pick_mdp_index(proving_value: &BigUint, mdp: &[BigUint]) -> Result<usize, HwError> {
    for i in (0..mdp.len()).rev() {
        if proving_value <= &mdp[i] {
            return Ok(i);
        }
    }
    Err(HwError::MdpError)
}

// Compute base's bitlength.
fn compute_bitlength(base: u32) -> usize {
    match base {
        2 => 1,
        4 => 2,
        16 => 4,
        256 => 8,
        _ => panic!(),
    }
}

fn final_smt_root<D: Hash>(
    top_salted_roots: &[[u8; 32]],
    shuffled_indexes: &[usize],
    tree_height: usize,
    smt_secret: &SmtSecret,
) -> Vec<u8> {
    let mut smt_leaves = compute_smt_leaves(top_salted_roots, shuffled_indexes, tree_height);
    smt_leaves.sort_by(|(t1, _), (t2, _)| t1.cmp(t2));
    let mut tree: Smt<node_template::HashWiresNodeSmt<D>> = Smt::new(tree_height);
    tree.build(&smt_leaves, smt_secret);
    tree.get_root_raw().serialize()
}

fn compute_smt_leaves<D: Hash>(
    top_salted_roots: &[[u8; 32]],
    shuffled_indexes: &[usize],
    tree_height: usize,
) -> Vec<(TreeIndex, node_template::HashWiresNodeSmt<D>)> {
    top_salted_roots
        .iter()
        .enumerate()
        .map(|(i, s)| {
            (
                TreeIndex::from_u32(tree_height, shuffled_indexes[i] as u32),
                node_template::HashWiresNodeSmt::<D>::new(s.to_vec()),
            )
        })
        .collect()
}

fn final_smt_root_and_proof<D: Hash>(
    top_salted_roots: &[[u8; 32]],
    shuffled_indexes: &[usize],
    tree_height: usize,
    leaf_index: usize,
    smt_secret: &SmtSecret,
) -> Result<(Vec<u8>, Vec<u8>), HwError> {
    let mut smt_leaves = compute_smt_leaves(top_salted_roots, shuffled_indexes, tree_height);

    let node = smt_leaves[leaf_index].0;

    smt_leaves.sort_by(|(t1, _), (t2, _)| t1.cmp(t2));
    let mut tree: Smt<node_template::HashWiresNodeSmt<D>> = Smt::new(tree_height);
    tree.build(&smt_leaves, smt_secret);

    let inclusion_proof =
        MerkleProof::<node_template::HashWiresNodeSmt<D>>::generate_inclusion_proof(&tree, &[node])
            .ok_or(HwError::InclusionProofError)?;
    let smt_proof = inclusion_proof.serialize();

    Ok((tree.get_root_raw().serialize(), smt_proof))
}

fn mdp_splits(mdp: &[BigUint], bitlength: usize) -> Vec<Vec<u8>> {
    mdp.iter()
        .map(|v| value_split_per_base(v, bitlength))
        .collect()
}

#[allow(clippy::type_complexity)]
fn plr_roots_and_proof<D: Hash>(
    seed: &[u8],
    wires: &[Vec<[u8; 32]>],
    max_length: usize,
    mdp_index: usize,
    proving_value_split_size: usize,
) -> (
    Vec<GenericArray<u8, PlrPaddingSize>>,
    Option<GenericArray<u8, PlrPaddingSize>>,
) {
    let plr: Vec<(
        GenericArray<u8, PlrPaddingSize>,
        Option<GenericArray<u8, PlrPaddingSize>>,
    )> = wires
        .iter()
        .map(|v| plr_accumulator::<D>(seed, v, max_length, proving_value_split_size))
        .collect();

    (plr.iter().map(|v| (*v).0).collect(), plr[mdp_index].1)
}

fn plr_roots<D: Hash>(
    seed: &[u8],
    wires: &[Vec<[u8; 32]>],
    max_length: usize,
) -> Vec<GenericArray<u8, PlrPaddingSize>> {
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

const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

fn log_2(x: u32) -> u32 {
    assert!(x > 0);
    num_bits::<u32>() as u32 - x.leading_zeros() - 1
}

fn compute_mdp_height(base: u32, max_number_bits: usize) -> u32 {
    log_2(max_number_bits as u32 / log_2(base))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hasher as Blake3;
    use num_traits::{FromPrimitive, Num};
    use rand_core::{OsRng, RngCore};
    use smtree::pad_secret::ALL_ZEROS_SECRET;
    use smtree::utils::print_output;

    // A full HashWires cycle with serialized outputs.
    fn prove_and_verify(
        base: u32,
        max_number_bits: usize,
        value: &BigUint,
        threshold: &BigUint,
    ) -> Result<(), HwError> {
        // Pick a random 32-byte seed.
        let mut rng = OsRng;
        let mut seed = vec![0u8; 32];
        rng.fill_bytes(&mut seed);

        // Generate secret.
        let secret = Secret::<Blake3>::gen(&seed, &value);

        // Generate and serialize commitment.
        let commitment = secret.commit(base, max_number_bits)?;
        let commitment_bytes = commitment.serialize();

        // Generate and serialize a HashWires proof.
        let proof = secret.prove(base, max_number_bits, &threshold)?;
        let proof_bytes = proof.serialize();

        // Verify a range proof over a commitment.
        commitment.verify(&proof, &threshold)?;
        Commitment::<Blake3>::deserialize(&commitment_bytes, base)
            .verify(&Proof::deserialize(&proof_bytes)?, &threshold)
    }

    #[test]
    fn test_proof_success() -> Result<(), HwError> {
        let value = BigUint::from_u32(402).unwrap();
        let threshold = BigUint::from_u32(378).unwrap();
        assert_eq!(true, prove_and_verify(4, 32, &value, &threshold).is_ok());
        Ok(())
    }

    #[test]
    fn test_proof_failure() -> Result<(), HwError> {
        let value = BigUint::from_u32(378).unwrap();
        let threshold = BigUint::from_u32(402).unwrap();
        assert_eq!(true, prove_and_verify(4, 32, &value, &threshold).is_ok());
        Ok(())
    }

    #[test]
    fn test_hashwires_inner_functions() -> Result<(), HwError> {
        let max_number_bits = 32;
        let base = 4;
        let mdp_tree_height = 4;
        let value = BigUint::from_str_radix("212", 4).unwrap();
        let seed = [0u8; 32];
        let threshold = BigUint::from_str_radix("201", 4).unwrap();
        let hw_commit_and_proof = larger_than_proof_gen::<Blake3>(
            &threshold,
            &value,
            base,
            &seed,
            max_number_bits,
            mdp_tree_height,
        )?;
        assert_eq!(
            hex::encode(&hw_commit_and_proof.0),
            "f2829e0e39d30fe589f79b866947bc93b9d6585193705bea3a5dc03eaa59eb02"
        );
        assert!(proof_verify::<Blake3>(
            &threshold,
            base,
            &hw_commit_and_proof.0,
            &hw_commit_and_proof.1,
            &hw_commit_and_proof.2,
            &hw_commit_and_proof.3,
            &hw_commit_and_proof.4
        )?);

        let max_digits = 32;
        let base = 16;
        let mdp_tree_height = 3;
        let value = BigUint::from_str_radix("1AB", 16).unwrap();
        let seed = [0u8; 32];
        let hw_commit = commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height)?;
        assert_eq!(
            hex::encode(hw_commit),
            "611a69247b1e60e269459546d6abc6c573e50b3edf50e61139ea57d416108892"
        );

        let max_digits = 64;
        let base = 256;
        let mdp_tree_height = 3;
        let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
        let seed = [0u8; 32];
        let hw_commit = commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height)?;
        assert_eq!(
            hex::encode(hw_commit),
            "2647d6e7aaa0c752f4adb7cff9274cb7f4f6a7952002741b85628dc8ac06a81e"
        );

        let max_digits = 128;
        let base = 256;
        let mdp_tree_height = 4;
        let value = BigUint::from_str_radix("23479534957845324957342523490585324", 10).unwrap();
        let seed = [0u8; 32];
        let hw_commit = commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height)?;
        assert_eq!(
            hex::encode(hw_commit),
            "6a896722c2328838d25ce63877e29d25b4a550d5c53f3c32f330f31d006bc9ca"
        );

        Ok(())
    }

    #[test]
    fn test_smt() -> Result<(), HwError> {
        let tree_height = 4;
        let mut tree: Smt<node_template::HashWiresNodeSmt<Blake3>> = Smt::new(tree_height);
        let mut v = vec![];
        let a = (
            TreeIndex::from_u32(tree_height, 0),
            node_template::HashWiresNodeSmt::<Blake3>::new(vec![1; 32]),
        );
        let b = (
            TreeIndex::from_u32(tree_height, 1),
            node_template::HashWiresNodeSmt::<Blake3>::new(vec![2; 32]),
        );
        let c = (
            TreeIndex::from_u32(tree_height, 15),
            node_template::HashWiresNodeSmt::<Blake3>::new(vec![3; 32]),
        );
        v.push(a);
        v.push(b);
        v.push(c);
        tree.build(&v, &ALL_ZEROS_SECRET);
        println!("{}", tree.get_leaves().len());
        print_output(&tree);

        Ok(())
    }

    #[test]
    fn test_pick_mdp_index() -> Result<(), HwError> {
        let mdp = vec![
            BigUint::from(3143u16),
            BigUint::from(3139u16),
            BigUint::from(3099u16),
            BigUint::from(2999u16),
        ];
        assert_eq!(pick_mdp_index(&BigUint::from(3142u16), &mdp)?, 0);
        assert_eq!(pick_mdp_index(&BigUint::from(3140u16), &mdp)?, 0);

        assert_eq!(pick_mdp_index(&BigUint::from(3139u16), &mdp)?, 1);
        assert_eq!(pick_mdp_index(&BigUint::from(3100u16), &mdp)?, 1);

        assert_eq!(pick_mdp_index(&BigUint::from(3099u16), &mdp)?, 2);
        assert_eq!(pick_mdp_index(&BigUint::from(3000u16), &mdp)?, 2);

        assert_eq!(pick_mdp_index(&BigUint::from(2999u16), &mdp)?, 3);
        assert_eq!(pick_mdp_index(&BigUint::from(0u16), &mdp)?, 3);

        Ok(())
    }
}
