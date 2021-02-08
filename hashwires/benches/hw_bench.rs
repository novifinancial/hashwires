use blake3::Hasher as Blake3;
use criterion::{criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;
use num_traits::Num;
use rand_core::{OsRng, RngCore};

use hashwires::hashwires::Secret;

pub fn hw_commitment_gen_base4(c: &mut Criterion) {
    let max_number_bits = 32;
    let base = 4;
    let value = BigUint::from_str_radix("212", 4).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    c.bench_function("hw_commitment_gen_base4", |bench| {
        bench.iter(|| secret.commit(base, max_number_bits))
    });
}

pub fn hw_commitment_gen_base16(c: &mut Criterion) {
    let max_number_bits = 32;
    let base = 16;
    let value = BigUint::from_str_radix("1AB", 16).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    c.bench_function("hw_commitment_gen_base16", |bench| {
        bench.iter(|| secret.commit(base, max_number_bits))
    });
}

pub fn hw_commitment_gen_base16_max(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 16;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    c.bench_function("hw_commitment_gen_base16_max", |bench| {
        bench.iter(|| secret.commit(base, max_number_bits))
    });
}

pub fn hw_commitment_gen_base256_max(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 256;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    c.bench_function("hw_commitment_gen_base256_max", |bench| {
        bench.iter(|| secret.commit(base, max_number_bits))
    });
}

pub fn hw_commitment_gen_base256_minimum_value(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 256;
    let value = BigUint::from_str_radix("1", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    c.bench_function("hw_commitment_gen_base256_minimum_value", |bench| {
        bench.iter(|| secret.commit(base, max_number_bits))
    });
}

pub fn hw_commitment_gen_base256_1million(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 256;
    let value = BigUint::from_str_radix("1000000", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    c.bench_function("hw_commitment_gen_base256_1million", |bench| {
        bench.iter(|| secret.commit(base, max_number_bits))
    });
}

pub fn hw_proof_gen_base4(c: &mut Criterion) {
    let max_number_bits = 32;
    let base = 4;
    let value = BigUint::from_str_radix("212", 4).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("201", 4).unwrap();

    c.bench_function("hw_proof_gen_base4", |bench| {
        bench.iter(|| secret.prove(base, max_number_bits, &threshold))
    });
}

pub fn hw_proof_gen_base16(c: &mut Criterion) {
    let max_number_bits = 32;
    let base = 16;
    let value = BigUint::from_str_radix("1AB", 16).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("CB", 16).unwrap();

    c.bench_function("hw_proof_gen_base16", |bench| {
        bench.iter(|| secret.prove(base, max_number_bits, &threshold))
    });
}

pub fn hw_proof_gen_base16_max(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 16;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("18446744073709551613", 10).unwrap();

    c.bench_function("hw_proof_gen_base16_max", |bench| {
        bench.iter(|| secret.prove(base, max_number_bits, &threshold))
    });
}

pub fn hw_proof_gen_base256_max(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 256;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("18446744073709551613", 10).unwrap();

    c.bench_function("hw_proof_gen_base256_max", |bench| {
        bench.iter(|| secret.prove(base, max_number_bits, &threshold))
    });
}

pub fn hw_proof_gen_base256_minimum_value(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 256;
    let value = BigUint::from_str_radix("1", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("1", 10).unwrap();

    c.bench_function("hw_proof_gen_base256_minimum_value", |bench| {
        bench.iter(|| secret.prove(base, max_number_bits, &threshold))
    });
}

pub fn hw_proof_gen_base256_1million(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 256;
    let value = BigUint::from_str_radix("1000000", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("500000", 10).unwrap();

    c.bench_function("hw_proof_gen_base256_1million", |bench| {
        bench.iter(|| secret.prove(base, max_number_bits, &threshold))
    });
}

pub fn hw_proof_verify_base4(c: &mut Criterion) {
    let max_number_bits = 32;
    let base = 4;
    let value = BigUint::from_str_radix("212", 4).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("201", 4).unwrap();
    let commitment = secret.commit(base, max_number_bits).unwrap();
    let proof = secret.prove(base, max_number_bits, &threshold).unwrap();

    c.bench_function("hw_proof_verify_base4", |bench| {
        bench.iter(|| commitment.verify(&proof, &threshold))
    });
}

pub fn hw_proof_verify_base16(c: &mut Criterion) {
    let max_number_bits = 32;
    let base = 16;
    let value = BigUint::from_str_radix("1AB", 16).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("CB", 16).unwrap();
    let commitment = secret.commit(base, max_number_bits).unwrap();
    let proof = secret.prove(base, max_number_bits, &threshold).unwrap();

    c.bench_function("hw_proof_verify_base16", |bench| {
        bench.iter(|| commitment.verify(&proof, &threshold))
    });
}

pub fn hw_proof_verify_base16_max(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 16;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("18446744073709551613", 10).unwrap();
    let commitment = secret.commit(base, max_number_bits).unwrap();
    let proof = secret.prove(base, max_number_bits, &threshold).unwrap();

    c.bench_function("hw_proof_verify_base16_max", |bench| {
        bench.iter(|| commitment.verify(&proof, &threshold))
    });
}

pub fn hw_proof_verify_base256_max(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 256;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("18446744073709551613", 10).unwrap();
    let commitment = secret.commit(base, max_number_bits).unwrap();
    let proof = secret.prove(base, max_number_bits, &threshold).unwrap();

    c.bench_function("hw_proof_verify_base256_max", |bench| {
        bench.iter(|| commitment.verify(&proof, &threshold))
    });
}

pub fn hw_proof_verify_base256_minimum_value(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 256;
    let value = BigUint::from_str_radix("1", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("1", 10).unwrap();
    let commitment = secret.commit(base, max_number_bits).unwrap();
    let proof = secret.prove(base, max_number_bits, &threshold).unwrap();

    c.bench_function("hw_proof_verify_base256_minimum_value", |bench| {
        bench.iter(|| commitment.verify(&proof, &threshold))
    });
}

pub fn hw_proof_verify_base256_1million(c: &mut Criterion) {
    let max_number_bits = 64;
    let base = 256;
    let value = BigUint::from_str_radix("1000000", 10).unwrap();

    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let secret = Secret::<Blake3>::gen(&seed, &value);

    let threshold = BigUint::from_str_radix("500000", 10).unwrap();
    let commitment = secret.commit(base, max_number_bits).unwrap();
    let proof = secret.prove(base, max_number_bits, &threshold).unwrap();

    c.bench_function("hw_proof_verify_base256_1million", |bench| {
        bench.iter(|| commitment.verify(&proof, &threshold))
    });
}

criterion_group!(
    hw_group,
    hw_commitment_gen_base4,
    hw_commitment_gen_base16,
    hw_commitment_gen_base16_max,
    hw_commitment_gen_base256_max,
    hw_commitment_gen_base256_minimum_value,
    hw_commitment_gen_base256_1million,
    hw_proof_gen_base4,
    hw_proof_gen_base16,
    hw_proof_gen_base16_max,
    hw_proof_gen_base256_max,
    hw_proof_gen_base256_minimum_value,
    hw_proof_gen_base256_1million,
    hw_proof_verify_base4,
    hw_proof_verify_base16,
    hw_proof_verify_base16_max,
    hw_proof_verify_base256_max,
    hw_proof_verify_base256_minimum_value,
    hw_proof_verify_base256_1million,
);
criterion_main!(hw_group);
