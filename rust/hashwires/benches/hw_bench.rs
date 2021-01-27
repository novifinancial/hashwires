use blake3::Hasher as Blake3;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;
use num_traits::Num;

use hashwires::hashwires::{bigger_than_proof_gen, commit_gen, proof_verify};

pub fn hw_commitment_gen_base4(c: &mut Criterion) {
    let max_digits = 32;
    let base = 4;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("212", 4).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base4", |bench| {
        bench.iter(|| commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

pub fn hw_commitment_gen_base16(c: &mut Criterion) {
    let max_digits = 32;
    let base = 16;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1AB", 16).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base16", |bench| {
        bench.iter(|| commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

pub fn hw_commitment_gen_base16_max(c: &mut Criterion) {
    let max_digits = 64;
    let base = 16;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base16_max", |bench| {
        bench.iter(|| commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

pub fn hw_commitment_gen_base256_max(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base256_max", |bench| {
        bench.iter(|| commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

pub fn hw_commitment_gen_base256_minimum_value(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1", 10).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base256_minimum_value", |bench| {
        bench.iter(|| commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

pub fn hw_commitment_gen_base256_1million(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1000000", 10).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base256_1million", |bench| {
        bench.iter(|| commit_gen::<Blake3>(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

pub fn hw_proof_gen_base4(c: &mut Criterion) {
    let max_digits = 32;
    let base = 4;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("212", 4).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("201", 4).unwrap();

    c.bench_function("hw_proof_gen_base4", |bench| {
        bench.iter(|| {
            bigger_than_proof_gen::<Blake3>(
                &proving_value,
                &value,
                base,
                &seed,
                max_digits,
                mdp_tree_height,
            )
        })
    });
}

pub fn hw_proof_gen_base16(c: &mut Criterion) {
    let max_digits = 32;
    let base = 16;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1AB", 16).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("CB", 16).unwrap();

    c.bench_function("hw_proof_gen_base16", |bench| {
        bench.iter(|| {
            bigger_than_proof_gen::<Blake3>(
                &proving_value,
                &value,
                base,
                &seed,
                max_digits,
                mdp_tree_height,
            )
        })
    });
}

pub fn hw_proof_gen_base16_max(c: &mut Criterion) {
    let max_digits = 64;
    let base = 16;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("18446744073709551613", 10).unwrap();

    c.bench_function("hw_proof_gen_base16_max", |bench| {
        bench.iter(|| {
            bigger_than_proof_gen::<Blake3>(
                &proving_value,
                &value,
                base,
                &seed,
                max_digits,
                mdp_tree_height,
            )
        })
    });
}

pub fn hw_proof_gen_base256_max(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("18446744073709551613", 10).unwrap();

    c.bench_function("hw_proof_gen_base256_max", |bench| {
        bench.iter(|| {
            bigger_than_proof_gen::<Blake3>(
                &proving_value,
                &value,
                base,
                &seed,
                max_digits,
                mdp_tree_height,
            )
        })
    });
}

pub fn hw_proof_gen_base256_minimum_value(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1", 10).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("1", 10).unwrap();

    c.bench_function("hw_proof_gen_base256_minimum_value", |bench| {
        bench.iter(|| {
            bigger_than_proof_gen::<Blake3>(
                &proving_value,
                &value,
                base,
                &seed,
                max_digits,
                mdp_tree_height,
            )
        })
    });
}

pub fn hw_proof_gen_base256_1million(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1000000", 10).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("500000", 10).unwrap();

    c.bench_function("hw_proof_gen_base256_1million", |bench| {
        bench.iter(|| {
            bigger_than_proof_gen::<Blake3>(
                &proving_value,
                &value,
                base,
                &seed,
                max_digits,
                mdp_tree_height,
            )
        })
    });
}

pub fn hw_proof_verify_base4(c: &mut Criterion) {
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
    );

    c.bench_function("hw_proof_verify_base4", |bench| {
        bench.iter(|| {
            proof_verify::<Blake3>(
                &proving_value,
                base,
                &hw_commit_and_proof.0,
                &hw_commit_and_proof.1,
                &hw_commit_and_proof.2,
                &hw_commit_and_proof.3,
                &hw_commit_and_proof.4,
            )
        })
    });
}

pub fn hw_proof_verify_base16(c: &mut Criterion) {
    let max_digits = 32;
    let base = 16;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1AB", 16).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("CB", 16).unwrap();
    let hw_commit_and_proof = bigger_than_proof_gen::<Blake3>(
        &proving_value,
        &value,
        base,
        &seed,
        max_digits,
        mdp_tree_height,
    );

    c.bench_function("hw_proof_verify_base16", |bench| {
        bench.iter(|| {
            proof_verify::<Blake3>(
                &proving_value,
                base,
                &hw_commit_and_proof.0,
                &hw_commit_and_proof.1,
                &hw_commit_and_proof.2,
                &hw_commit_and_proof.3,
                &hw_commit_and_proof.4,
            )
        })
    });
}

pub fn hw_proof_verify_base16_max(c: &mut Criterion) {
    let max_digits = 64;
    let base = 16;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("18446744073709551613", 10).unwrap();
    let hw_commit_and_proof = bigger_than_proof_gen::<Blake3>(
        &proving_value,
        &value,
        base,
        &seed,
        max_digits,
        mdp_tree_height,
    );

    c.bench_function("hw_proof_verify_base16_max", |bench| {
        bench.iter(|| {
            proof_verify::<Blake3>(
                &proving_value,
                base,
                &hw_commit_and_proof.0,
                &hw_commit_and_proof.1,
                &hw_commit_and_proof.2,
                &hw_commit_and_proof.3,
                &hw_commit_and_proof.4,
            )
        })
    });
}

pub fn hw_proof_verify_base256_max(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("18446744073709551613", 10).unwrap();
    let hw_commit_and_proof = bigger_than_proof_gen::<Blake3>(
        &proving_value,
        &value,
        base,
        &seed,
        max_digits,
        mdp_tree_height,
    );

    c.bench_function("hw_proof_verify_base256_max", |bench| {
        bench.iter(|| {
            proof_verify::<Blake3>(
                &proving_value,
                base,
                &hw_commit_and_proof.0,
                &hw_commit_and_proof.1,
                &hw_commit_and_proof.2,
                &hw_commit_and_proof.3,
                &hw_commit_and_proof.4,
            )
        })
    });
}

pub fn hw_proof_verify_base256_minimum_value(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1", 10).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("1", 10).unwrap();
    let hw_commit_and_proof = bigger_than_proof_gen::<Blake3>(
        &proving_value,
        &value,
        base,
        &seed,
        max_digits,
        mdp_tree_height,
    );

    c.bench_function("hw_proof_verify_base256_minimum_value", |bench| {
        bench.iter(|| {
            proof_verify::<Blake3>(
                &proving_value,
                base,
                &hw_commit_and_proof.0,
                &hw_commit_and_proof.1,
                &hw_commit_and_proof.2,
                &hw_commit_and_proof.3,
                &hw_commit_and_proof.4,
            )
        })
    });
}

pub fn hw_proof_verify_base256_1million(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1000000", 10).unwrap();
    let seed = [0u8; 32];

    let proving_value = BigUint::from_str_radix("500000", 10).unwrap();
    let hw_commit_and_proof = bigger_than_proof_gen::<Blake3>(
        &proving_value,
        &value,
        base,
        &seed,
        max_digits,
        mdp_tree_height,
    );

    c.bench_function("hw_proof_verify_base256_1million", |bench| {
        bench.iter(|| {
            proof_verify::<Blake3>(
                &proving_value,
                base,
                &hw_commit_and_proof.0,
                &hw_commit_and_proof.1,
                &hw_commit_and_proof.2,
                &hw_commit_and_proof.3,
                &hw_commit_and_proof.4,
            )
        })
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
