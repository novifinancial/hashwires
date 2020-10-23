use num_bigint::BigUint;
use num_traits::Num;

pub fn num_base_digits(max_digits: u32, base: u32, num: &BigUint) -> u32 {
    let mut temp = BigUint::from_str_radix(&*base.to_string(), 10).unwrap();
    // max_num = base_bigint.unwrap().pow(max_digits).sub(BigUint::one());
    for i in 0..max_digits {
        if temp > *num {
            return i;
        }
        temp = temp.pow(i + 1);
    }
    // TODO: return an error
    1024
}

pub fn num_base_padding_zeros(max_digits: u32, base: u32, num: &BigUint) -> u32 {
    max_digits - num_base_digits(max_digits, base, num)
}

#[test]
fn test_padding() {
    let num = BigUint::from_str_radix(&25.to_string(), 10).unwrap();
    let max_digits = 14;
    let base = 10;
    assert_eq!(2, num_base_digits(max_digits, base, &num));
    assert_eq!(
        max_digits - 2,
        num_base_padding_zeros(max_digits, base, &num)
    );
}
