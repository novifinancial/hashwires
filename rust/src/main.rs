mod primitives;

use blake2::{Blake2b, Digest};
use hex;
use crate::primitives::find_dp;

const HASHLEN: usize = 5;

fn main() {
    let seed = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0,
        0, 0, 0,
    ];
    println!("Hello, world! Generating a few nums bases:");
    //  println!({:?}, decode(String::from("DEAD")));

    println!("{:?}", find_dp(3413, 10));
    println!("{:?}", find_dp(2999, 10));
    println!("{:?}", find_dp(181, 10));
    println!("{:?}", find_dp(1979, 10));
    println!("{:?}", find_dp(1992, 10));
    println!("{:?}", find_dp(1799, 10));
    println!("{:?}", find_dp(1700, 10));
    println!("{:?}", find_dp(1000, 10));
    println!("{:?}", find_dp(100099, 10));

    let t = String::from("Test");
    let h = hash(t.clone());
    println!("{:?}", h);

    let b = decode(h.clone());
    println!("{:?}", b.len())
}

fn hash(value: String) -> String {
    let mut hasher = Blake2b::new();
    hasher.update(value);
    let ret = hasher.finalize();
    encode(&ret[0..HASHLEN])
}

fn encode(value: &[u8]) -> String {
    hex::encode(value)
}

fn decode(text: String) -> Vec<u8> {
    match hex::decode(text) {
        Err(why) => panic!("{:?}", why),
        Ok(res) => res,
    }
}
