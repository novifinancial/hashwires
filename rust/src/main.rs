extern crate blake2;

use blake2::{Blake2b, Digest};
use hex;
use std::collections::HashSet;

const HASHLEN: usize = 5;

fn main() {
    println!("Hello, world! Generating a few nums bases:");
    //  println!({:?}, decode(String::from("DEAD")));

    println!("{:?}", find_complete(3413, 10));
    println!("{:?}", find_complete(2999, 10));
    println!("{:?}", find_complete(181, 10));
    println!("{:?}", find_complete(1979, 10));
    println!("{:?}", find_complete(1992, 10));
    println!("{:?}", find_complete(1799, 10));
    println!("{:?}", find_complete(1700, 10));
    println!("{:?}", find_complete(1000, 10));
    println!("{:?}", find_complete(100099, 10));

    let t = String::from("Test");
    let h = hash(t.clone());
    println!("{:?}", h);

    let b = decode(h.clone());
    println!("{:?}", b.len())
}

fn hash(value: String) -> String {
    let mut hasher = Blake2b::new();
    hasher.update((value));
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

// notice this is done using u32 for now, we might want to move to big integers instead
fn find_complete(value: u32, base: u32) -> Vec<u32> {
    let mut exp: u32 = base;
    let mut ret: Vec<u32> = Vec::new();
    let mut set = HashSet::new();

    set.insert(value);
    while exp < value {
        let mut prev = value;

        // optimizing out the unneeded values. Notice this still needs optimization to avoid
        // duplicated values. Maybe I could just use a set instead of an Vec?
        if (prev + 1) % exp != 0 {
            //  (x//b^i - 1) * b^i + (b-1)
            prev = (prev / exp - 1) * exp + (exp - 1);
            set.insert(prev);
        }
        exp = exp * base;
    }
    for x in set.iter() {
        ret.push(*x);
    }
    ret.sort();
    ret.reverse();
    ret
}
