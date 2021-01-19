use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;
use num_traits::Num;

use hashwires::hashwires::commit_gen;

pub fn hw_commitment_gen_base4(c: &mut Criterion) {
    let max_digits = 32;
    let base = 4;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("212", 4).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base4", |bench| {
        bench.iter(|| commit_gen(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

pub fn hw_commitment_gen_base16(c: &mut Criterion) {
    let max_digits = 32;
    let base = 16;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("1AB", 16).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base16", |bench| {
        bench.iter(|| commit_gen(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

pub fn hw_commitment_gen_base16_max(c: &mut Criterion) {
    let max_digits = 64;
    let base = 16;
    let mdp_tree_height = 4;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base16_max", |bench| {
        bench.iter(|| commit_gen(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

pub fn hw_commitment_gen_base256_max(c: &mut Criterion) {
    let max_digits = 64;
    let base = 256;
    let mdp_tree_height = 3;
    let value = BigUint::from_str_radix("18446744073709551614", 10).unwrap();
    let seed = [0u8; 32];

    c.bench_function("hw_commitment_gen_base256_max", |bench| {
        bench.iter(|| commit_gen(&value, base, &seed, max_digits, mdp_tree_height))
    });
}

criterion_group!(
    hw_group,
    hw_commitment_gen_base4,
    hw_commitment_gen_base16,
    hw_commitment_gen_base16_max,
    hw_commitment_gen_base256_max,
);
criterion_main!(hw_group);
