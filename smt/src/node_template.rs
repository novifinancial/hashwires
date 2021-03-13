use std::marker::PhantomData;

use digest::Digest;
use rand::Rng;

use crate::{
    error::DecodingError,
    index::TreeIndex,
    traits::{
        Mergeable, Paddable, PaddingProvable, ProofExtractable, Rand, Serializable, TypeName,
    },
    utils::{bytes_to_usize, usize_to_bytes},
};
use crate::pad_secret::Secret;

const SECRET: &str = "secret";
pub const PADDING_STRING: &str = "padding_node";

/// An SMT node that carries just a hash value
#[derive(Default, Clone, Debug)]
pub struct HashNodeSmt<D> {
    hash: Vec<u8>,
    phantom: PhantomData<D>,
}

impl<D> HashNodeSmt<D> {
    pub fn new(hash: Vec<u8>) -> HashNodeSmt<D> {
        HashNodeSmt {
            hash,
            phantom: PhantomData,
        }
    }
}

impl<D> PartialEq for HashNodeSmt<D> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl<D> Eq for HashNodeSmt<D> {}

impl<D: Digest> Mergeable for HashNodeSmt<D> {
    fn merge(lch: &HashNodeSmt<D>, rch: &HashNodeSmt<D>) -> HashNodeSmt<D> {
        let mut hasher = D::new();
        hasher.update(&lch.hash);
        hasher.update(&rch.hash);
        HashNodeSmt::new(hasher.finalize().to_vec())
    }
}

impl<D: Digest> Paddable for HashNodeSmt<D> {
    fn padding(idx: &TreeIndex, secret: &Secret) -> HashNodeSmt<D> {
        let mut pre_image = D::new();
        pre_image.update(secret.as_bytes());
        pre_image.update(&TreeIndex::serialize(&[*idx]));

        let mut hasher = D::new();
        hasher.update(PADDING_STRING.as_bytes());
        hasher.update(&pre_image.finalize().to_vec());
        HashNodeSmt::new(hasher.finalize().to_vec())
    }
}

impl<D: Digest> Serializable for HashNodeSmt<D> {
    fn serialize(&self) -> Vec<u8> {
        (&self.hash).clone()
    }

    fn deserialize_as_a_unit(bytes: &[u8], begin: &mut usize) -> Result<Self, DecodingError> {
        if bytes.len() - *begin < D::output_size() {
            return Err(DecodingError::BytesNotEnough);
        }
        let item = Self::new(bytes[*begin..*begin + D::output_size()].to_vec());
        *begin += D::output_size();
        Ok(item)
    }
}

impl<D: Clone> ProofExtractable for HashNodeSmt<D> {
    type ProofNode = HashNodeSmt<D>;
    fn get_proof_node(&self) -> Self::ProofNode {
        self.clone()
    }
}

impl<D: Clone + Digest> PaddingProvable for HashNodeSmt<D> {
    type PaddingProof = HashNodeSmt<D>;

    fn prove_padding_node(&self, idx: &TreeIndex) -> HashNodeSmt<D> {
        let data = TreeIndex::serialize(&[*idx]);
        let mut pre_image = D::new();
        pre_image.update(SECRET.as_bytes());
        pre_image.update(&data);
        HashNodeSmt::new(pre_image.finalize().to_vec())
    }

    fn verify_padding_node(
        node: &<Self as ProofExtractable>::ProofNode,
        proof: &Self::PaddingProof,
        _idx: &TreeIndex,
    ) -> bool {
        let mut hasher = D::new();
        hasher.update(PADDING_STRING.as_bytes());
        hasher.update(&proof.hash);
        *node == HashNodeSmt::<D>::new(hasher.finalize().to_vec())
    }
}

impl<D: Digest> Rand for HashNodeSmt<D> {
    fn randomize(&mut self) {
        *self = HashNodeSmt::new(vec![0u8; D::output_size()]);
        let mut rng = rand::thread_rng();
        for item in &mut self.hash {
            *item = rng.gen();
        }
    }
}

impl<D: TypeName> TypeName for HashNodeSmt<D> {
    fn get_name() -> String {
        format!("Hash ({})", D::get_name())
    }
}

impl TypeName for blake3::Hasher {
    fn get_name() -> String {
        "Blake3".to_owned()
    }
}

impl TypeName for blake2::Blake2b {
    fn get_name() -> String {
        "Blake2b".to_owned()
    }
}

impl TypeName for sha2::Sha256 {
    fn get_name() -> String {
        "Sha2".to_owned()
    }
}

impl TypeName for sha3::Sha3_256 {
    fn get_name() -> String {
        "Sha3".to_owned()
    }
}

/// An SMT node that carries a u64 value, and merging is computed as the sum of two nodes.
#[derive(Default, Clone, Debug)]
pub struct SumNodeSmt(u64);

impl SumNodeSmt {
    pub fn new(value: u64) -> SumNodeSmt {
        SumNodeSmt(value)
    }
}

impl PartialEq for SumNodeSmt {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SumNodeSmt {}

impl Mergeable for SumNodeSmt {
    fn merge(lch: &SumNodeSmt, rch: &SumNodeSmt) -> SumNodeSmt {
        SumNodeSmt(lch.0 + rch.0)
    }
}

impl Paddable for SumNodeSmt {
    fn padding(_idx: &TreeIndex, _secret: &Secret) -> SumNodeSmt {
        SumNodeSmt(0u64)
    }
}

impl Serializable for SumNodeSmt {
    fn serialize(&self) -> Vec<u8> {
        usize_to_bytes(self.0 as usize, 8)
    }

    fn deserialize_as_a_unit(bytes: &[u8], begin: &mut usize) -> Result<Self, DecodingError> {
        if bytes.len() - *begin < 8 {
            return Err(DecodingError::BytesNotEnough);
        }
        Ok(SumNodeSmt(bytes_to_usize(bytes, 8, begin).unwrap() as u64))
    }
}

impl ProofExtractable for SumNodeSmt {
    type ProofNode = SumNodeSmt;
    fn get_proof_node(&self) -> Self::ProofNode {
        SumNodeSmt(self.0)
    }
}

impl PaddingProvable for SumNodeSmt {
    type PaddingProof = SumNodeSmt;
    fn prove_padding_node(&self, _idx: &TreeIndex) -> SumNodeSmt {
        SumNodeSmt(0)
    }
    fn verify_padding_node(node: &SumNodeSmt, proof: &SumNodeSmt, _idx: &TreeIndex) -> bool {
        node.0 == 0 && proof.0 == 0
    }
}

impl Rand for SumNodeSmt {
    fn randomize(&mut self) {
        let mut rng = rand::thread_rng();
        let x: u32 = rng.gen();
        self.0 = x as u64;
    }
}

impl TypeName for SumNodeSmt {
    fn get_name() -> String {
        "Sum".to_owned()
    }
}
