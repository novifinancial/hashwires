use std::collections::HashSet;

/// Find denominating partition of a numeric `value` in some input `base`.
/// This currently works for u32 only.
pub fn find_dp_u32(value: u32, base: u32) -> Vec<u32> {
    let mut exp: u32 = base;
    let mut ret: Vec<u32> = Vec::new();
    // TODO: Check if HashSets are expensive
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

#[test]
fn test_dp() {
    // base10
    assert_eq!(find_dp_u32(3413, 10), vec![3413, 3409, 3399, 2999]);
    assert_eq!(find_dp_u32(2999, 10), vec![2999]);
    assert_eq!(find_dp_u32(181, 10), vec![181, 179, 99]);
    assert_eq!(find_dp_u32(1979, 10), vec![1979, 1899, 999]);
    assert_eq!(find_dp_u32(1992, 10), vec![1992, 1989, 1899, 999]);
    assert_eq!(find_dp_u32(1799, 10), vec![1799, 999]);
    assert_eq!(find_dp_u32(1700, 10), vec![1700, 1699, 999]);
    assert_eq!(find_dp_u32(1000, 10), vec![1000, 999]);
    assert_eq!(find_dp_u32(100099, 10), vec![100099, 99999]);

    //base4
    assert_eq!(find_dp_u32(312, 4), vec![312, 303, 233]);
}
