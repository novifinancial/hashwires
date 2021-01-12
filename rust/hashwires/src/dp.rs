use num_bigint::BigUint;
use num_traits::{Num, One, Zero};

/// Find dominating partition of a string `value` in some input `base`.
/// This is using BigUint and is returning a Vec of String in the same `base`.
#[allow(dead_code)]
pub fn find_dp_u32(value: &str, base: u32) -> Vec<String> {
    let mut exp = BigUint::new(vec![base]);
    let mut ret: Vec<String> = Vec::new();

    let val = BigUint::from_str_radix(value, base).unwrap();
    let val_plus1 = &val + BigUint::one();

    ret.push(val.to_str_radix(base).to_string());
    let mut prev = val.clone();
    while exp < val {
        // optimizing out the unneeded values to get a minimal dominating partition
        if &val_plus1 % &exp != BigUint::zero() {
            //  (x//b^i - 1) * b^i + (b-1)
            // set.insert((&val / &exp * &exp - &one).to_str_radix(base));
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
    ret.sort();
    ret.reverse();
    ret
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

    // // base16
    // assert_eq!(
    //     to_ints(find_dp_u32("3413", 16)),
    //     vec![3413, 3409, 3399, 2999]
    // );
    //
    // // 256. Please complete this test when base-256 is supported.
    // assert_eq!(to_ints(find_dp_u32("42342346", 256)), vec![312, 303, 233]);
}
