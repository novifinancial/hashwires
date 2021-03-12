use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

const BIT_SIZE: usize = 64;

// const SINGLE_PROOF_BYTE_NUM: usize = 672;
// const PROOF_SIZE_BYTE_NUM: usize = 8;
// const AGGREGATED_NUM_BYTE_NUM: usize = 2;
// const INDIVIDUAL_NUM_BYTE_NUM: usize = 8;

pub fn bp_proof_gen(c: &mut Criterion) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(BIT_SIZE, 1);
    let mut transcript = Transcript::new(&[]);
    let secret: u64 = 18446744073709551614u64;
    let blinding: Scalar = Scalar::from_bits([7u8; 32]);

    c.bench_function("bp_proof_gen", |bench| {
        bench.iter(|| {
            RangeProof::prove_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                secret,
                &blinding,
                BIT_SIZE,
            )
        })
    });
}

pub fn bp_proof_gen_small_value(c: &mut Criterion) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(BIT_SIZE, 1);
    let mut transcript = Transcript::new(&[]);
    let secret: u64 = 1u64;
    let blinding: Scalar = Scalar::from(11u64);

    c.bench_function("bp_proof_gen_small_value", |bench| {
        bench.iter(|| {
            RangeProof::prove_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                secret,
                &blinding,
                BIT_SIZE,
            )
        })
    });
}

pub fn bp_proof_verify(c: &mut Criterion) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(BIT_SIZE, 1);
    let mut transcript = Transcript::new(&[]);
    let secret: u64 = 18446744073709551614u64;
    let blinding: Scalar = Scalar::from(11u64);
    let (bp_proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        secret,
        &blinding,
        BIT_SIZE,
    )
    .unwrap();

    c.bench_function("bp_proof_verify", |bench| {
        bench.iter(|| {
            bp_proof.verify_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &committed_value,
                BIT_SIZE,
            )
        })
    });
}

criterion_group!(
    bp_group,
    bp_proof_gen,
    bp_proof_gen_small_value,
    bp_proof_verify
);
criterion_main!(bp_group);
