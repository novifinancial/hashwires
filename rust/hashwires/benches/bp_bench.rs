use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use sha2::Sha512;

const BIT_SIZE: usize = 64;

const SINGLE_PROOF_BYTE_NUM: usize = 672;
const PROOF_SIZE_BYTE_NUM: usize = 8;
const AGGREGATED_NUM_BYTE_NUM: usize = 2;
const INDIVIDUAL_NUM_BYTE_NUM: usize = 8;

pub fn bp_proof_gen(c: &mut Criterion) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(BIT_SIZE, 1);
    let mut prover_transcript = Transcript::new(&[]);
    let secret: u64 = 18446744073709551614u64;
    let blinding: Scalar = Scalar::from(11u64);

    c.bench_function("bp_proof_gen", |bench| {
        bench.iter(|| {
            RangeProof::prove_single(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                secret,
                &blinding,
                BIT_SIZE,
            )
        })
    });
}

criterion_group!(bp_group, bp_proof_gen,);
criterion_main!(bp_group);
