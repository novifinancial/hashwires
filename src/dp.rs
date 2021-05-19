use num_bigint::BigUint;
use num_traits::{Num, One, Zero};

/// Find dominating partition of a string `value` in some input `base` (any base).
pub(crate) fn find_mdp(value: &BigUint, base: u32) -> Vec<BigUint> {
    let mut exp = BigUint::from(base);
    let mut ret: Vec<BigUint> = Vec::new();

    let val_plus1 = value + BigUint::one();
    ret.push(value.clone());
    let mut prev = value.clone();

    while exp < *value {
        // optimizing out the unneeded values to get a minimal dominating partition
        if &val_plus1 % &exp != BigUint::zero() {
            //  (x//b^i - 1) * b^i + (b-1)
            let temp = value / &exp * &exp - BigUint::one();
            if prev != temp {
                ret.push(temp.clone());
                prev = temp;
            }
        }
        exp *= base;
    }
    ret
}

/// This gets the `index`-th value of `msg` split into `bitlength` pieces.
///
/// # Panics
///
/// This function panics if index is out of bounds, or bitlength is not in the set {1, 2, 4, 8}.
/// Thus, it currently works for bases 2^1 = 2, 2^2 = 4 , 2^4 = 16 and 2^8 = 256 only
fn coef(msg: &[u8], index: usize, bitlength: usize) -> u8 {
    match bitlength {
        8 => msg[index],
        4 => {
            let ix = index / 2;
            let byte = msg[ix];
            match index % 2 {
                0 => byte >> 4,
                1 => byte & 0xf,
                _ => unreachable!(),
            }
        }
        2 => {
            let ix = index / 4;
            let byte = msg[ix];
            match index % 4 {
                0 => byte >> 6,
                1 => (byte >> 4) & 0x3,
                2 => (byte >> 2) & 0x3,
                3 => byte & 0x3,
                _ => unreachable!(),
            }
        }
        1 => {
            let ix = index / 8;
            let byte = msg[ix];
            match index % 8 {
                0 => byte >> 7,
                1 => (byte >> 6) & 0x1,
                2 => (byte >> 5) & 0x1,
                3 => (byte >> 4) & 0x1,
                4 => (byte >> 3) & 0x1,
                5 => (byte >> 2) & 0x1,
                6 => (byte >> 1) & 0x1,
                7 => byte & 0x1,
                _ => unreachable!(),
            }
        }
        _ => unimplemented!(),
    }
}

// TODO: it currently works for bases 2, 4, 16, 256 (bitlength 1, 2, 4, 8) only
/// Split value, based on base in bitlength, (supports bitlength 1, 2, 4, 8).
pub(crate) fn value_split_per_base(value: &BigUint, bitlength: usize) -> Vec<u8> {
    let v_bytes = value.to_bytes_be();
    let v = v_bytes.as_slice();

    let mut ret: Vec<u8> = Vec::new();
    for i in 0..v.len() * 8 / bitlength {
        let coef = coef(v, i, bitlength);
        if !(ret.is_empty() && coef == 0) {
            // throw leading zeros
            ret.push(coef);
        }
    }
    ret
}

/// For demonstration purposes only, not used in the main Hashwires implementation.
/// Find dominating partition of a string `value` in some input `base` (works up to base 10).
/// This is using BigUint and is returning a Vec of String in the same `base`.
#[allow(dead_code)]
fn find_dp_u32(value: &str, base: u32) -> Vec<String> {
    let mut exp = BigUint::new(vec![base]);
    let mut ret: Vec<String> = Vec::new();

    let val = BigUint::from_str_radix(value, base).unwrap();
    let val_plus1 = &val + BigUint::one();

    ret.push(val.to_str_radix(base));
    // We use prev to detect consecutive duplicate entries (a trick to avoid HashSet)
    let mut prev = val.clone();
    while exp < val {
        // optimizing out the unneeded values to get a minimal dominating partition
        if &val_plus1 % &exp != BigUint::zero() {
            //  (x//b^i - 1) * b^i + (b-1)
            let temp = &val / &exp * &exp - BigUint::one();
            if prev != temp {
                ret.push(temp.to_str_radix(base).to_string());
                prev = temp;
            }
        }
        exp *= base;
    }
    ret
}

/// to_ints is a function used for the tests to easily compare with Vec<u32>
#[allow(dead_code)]
fn to_ints(vals: Vec<String>) -> Vec<u32> {
    let mut ret: Vec<u32> = Vec::new();
    for i in vals {
        let v = i.parse::<u32>().unwrap();
        ret.push(v);
    }
    ret.sort_unstable();
    ret.reverse();
    ret
}

/// Find dominating partition of a u32 integer `value` in some u32 input `base`.
/// This is for demonstration purposes and included in the HashWires paper.
#[allow(dead_code)]
fn find_mdp_u32(value: u32, base: u32) -> Vec<u32> {
    let mut exp = base;
    let mut ret: Vec<u32> = vec![value];
    let mut prev = value;

    while exp < value {
        if (value + 1) % exp != 0 {
            let temp = value / exp * exp - 1;
            if prev != temp {
                ret.push(temp);
                prev = temp;
            }
        }
        exp *= base;
    }
    ret
}

#[test]
fn test_mdp_u32() {
    let mdp_u32 = find_mdp_u32(8733432, 10);
    assert_eq!(
        mdp_u32,
        vec![8733432, 8733429, 8733399, 8732999, 8729999, 8699999, 7999999]
    );
    let mdp_u32 = find_mdp_u32(3413, 10);
    assert_eq!(mdp_u32, vec![3413, 3409, 3399, 2999]);
    let mdp_u32 = find_mdp_u32(9999, 16);
    assert_eq!(mdp_u32, vec![9999, 9983, 8191]);
    let mdp_u32 = find_mdp_u32(255, 2);
    assert_eq!(mdp_u32, vec![255]);
    let mdp_u32 = find_mdp_u32(254, 2);
    assert_eq!(mdp_u32, vec![254, 253, 251, 247, 239, 223, 191, 127]);
}

#[test]
fn test_dp() {
    // base10
    assert_eq!(
        to_ints(find_dp_u32("3413", 10)),
        vec![3413, 3409, 3399, 2999]
    );
    assert_eq!(to_ints(find_dp_u32("2999", 10)), vec![2999]);
    assert_eq!(to_ints(find_dp_u32("181", 10)), vec![181, 179, 99]);
    assert_eq!(to_ints(find_dp_u32("1979", 10)), vec![1979, 1899, 999]);
    assert_eq!(
        to_ints(find_dp_u32("1992", 10)),
        vec![1992, 1989, 1899, 999]
    );
    assert_eq!(to_ints(find_dp_u32("1799", 10)), vec![1799, 999]);
    assert_eq!(to_ints(find_dp_u32("1700", 10)), vec![1700, 1699, 999]);
    assert_eq!(to_ints(find_dp_u32("1000", 10)), vec![1000, 999]);
    assert_eq!(to_ints(find_dp_u32("999", 10)), vec![999]);
    assert_eq!(to_ints(find_dp_u32("100099", 10)), vec![100099, 99999]);

    // base4
    assert_eq!(to_ints(find_dp_u32("312", 4)), vec![312, 303, 233]);
    assert_eq!(to_ints(find_dp_u32("311", 4)), vec![311, 303, 233]);
    assert_eq!(to_ints(find_dp_u32("310", 4)), vec![310, 303, 233]);
    assert_eq!(to_ints(find_dp_u32("322", 4)), vec![322, 313, 233]);
    assert_eq!(to_ints(find_dp_u32("233", 4)), vec![233]);
}

#[test]
fn test_mdp() {
    // base4
    assert_eq!(
        find_mdp(&BigUint::from_str_radix("312", 4).unwrap(), 4),
        vec![
            BigUint::from_str_radix("312", 4).unwrap(),
            BigUint::from_str_radix("303", 4).unwrap(),
            BigUint::from_str_radix("233", 4).unwrap(),
        ]
    );

    // base10
    assert_eq!(
        find_mdp(&BigUint::from(3413u32), 10),
        vec![
            BigUint::from(3413u32),
            BigUint::from(3409u32),
            BigUint::from(3399u32),
            BigUint::from(2999u32),
        ]
    );

    // base16
    assert_eq!(
        find_mdp(&BigUint::from_str_radix("D55", 16).unwrap(), 16),
        vec![
            BigUint::from_str_radix("D55", 16).unwrap(),
            BigUint::from_str_radix("D4F", 16).unwrap(),
            BigUint::from_str_radix("CFF", 16).unwrap(),
        ]
    );

    // base36
    assert_eq!(
        find_mdp(&BigUint::from_str_radix("2MT", 36).unwrap(), 36),
        vec![
            BigUint::from_str_radix("2MT", 36).unwrap(),
            BigUint::from_str_radix("2LZ", 36).unwrap(),
            BigUint::from_str_radix("1ZZ", 36).unwrap(),
        ]
    );

    // base256
    assert_eq!(
        find_mdp(&BigUint::from_str_radix("65535", 10).unwrap(), 256),
        vec![BigUint::from_str_radix("65535", 10).unwrap()]
    );

    // base256 more complex: (256^3 - 7) = 16777209
    assert_eq!(
        find_mdp(&BigUint::from_str_radix("16777209", 10).unwrap(), 256),
        vec![
            // 16777209 (decimal) = 1111_1111_1111_1111_1111_1001 (binary)
            BigUint::from_str_radix("16777209", 10).unwrap(),
            // 16776959 (decimal) = 1111_1111_1111_1110_1111_1111 (binary)
            BigUint::from_str_radix("16776959", 10).unwrap(),
            // 16711679 (decimal) = 1111_1110_1111_1111_1111_1111 (binary)
            BigUint::from_str_radix("16711679", 10).unwrap(),
        ]
    );
}

#[test]
fn test_coef() {
    // base2 = 2^1
    let number = BigUint::from_str_radix("0010101111010101", 2).unwrap();
    let splits = value_split_per_base(&number, 1);
    assert_eq!(splits, vec![1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1]);

    // base4 = 2^2
    let number = BigUint::from_str_radix("0010101111010101", 2).unwrap();
    let splits = value_split_per_base(&number, 2);
    assert_eq!(splits, vec![2, 2, 3, 3, 1, 1, 1]);

    // base4 = 2^2
    let number = BigUint::from_str_radix("312", 4).unwrap();
    let splits = value_split_per_base(&number, 2);
    assert_eq!(splits, vec![3, 1, 2]);

    // base16 = 2^4
    let number = BigUint::from_str_radix("D55", 16).unwrap();
    let splits = value_split_per_base(&number, 4);
    assert_eq!(splits, vec![13, 5, 5]);

    // base256 = 2^8
    // 16777209 (decimal) = 1111_1111_1111_1111_1111_1001 (binary)
    let number = &BigUint::from_str_radix("16777209", 10).unwrap();
    let splits = value_split_per_base(&number, 8);
    assert_eq!(splits, vec![255, 255, 249]);
}
