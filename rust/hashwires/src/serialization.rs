use crate::errors::HWError;

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp(input: usize, length: usize) -> Vec<u8> {
    if length <= std::mem::size_of::<usize>() {
        return (&input.to_be_bytes()[std::mem::size_of::<usize>() - length..]).to_vec();
    }

    let mut output = vec![0u8; length];
    output.splice(
        length - std::mem::size_of::<usize>()..length,
        input.to_be_bytes().iter().cloned(),
    );
    output
}

// Corresponds to the OS2IP() function from RFC8017
pub(crate) fn os2ip(input: &[u8]) -> Result<usize, HWError> {
    if input.len() > std::mem::size_of::<usize>() {
        return Err(HWError::SerializationError);
    }

    let mut output_array = [0u8; std::mem::size_of::<usize>()];
    output_array[std::mem::size_of::<usize>() - input.len()..].copy_from_slice(input);
    Ok(usize::from_be_bytes(output_array))
}

// Computes I2OSP(len(input), max_bytes) || input
pub(crate) fn serialize(input: &[u8], max_bytes: usize) -> Vec<u8> {
    [&i2osp(input.len(), max_bytes), &input[..]].concat()
}

// Tokenizes an input of the format I2OSP(len(input), max_bytes) || input, outputting
// (input, remainder)
pub(crate) fn tokenize(input: &[u8], size_bytes: usize) -> Result<(Vec<u8>, Vec<u8>), HWError> {
    if size_bytes > std::mem::size_of::<usize>() || input.len() < size_bytes {
        return Err(HWError::SerializationError);
    }

    let size = os2ip(&input[..size_bytes])?;
    if size_bytes + size > input.len() {
        return Err(HWError::SerializationError);
    }

    Ok((
        input[size_bytes..size_bytes + size].to_vec(),
        input[size_bytes + size..].to_vec(),
    ))
}

// Returns a slice of input of length len along with the remainder, throwing an error if it is
// too short
pub(crate) fn take_slice(input: &[u8], len: usize) -> Result<(&[u8], &[u8]), HWError> {
    if input.len() < len {
        return Err(HWError::SerializationError);
    }
    Ok((&input[..len], &input[len..]))
}

#[cfg(test)]
mod tests {
    use super::serialize;
    use crate::errors::HWError;
    use crate::hashwires::{HWProof, HashWires};
    use blake3::Hasher as Blake3;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_commit_serialization() -> Result<(), HWError> {
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        let hw = HashWires::<Blake3>::deserialize(&bytes, 4, 32);
        let output = hw.serialize();

        assert_eq!(bytes.to_vec(), output);
        Ok(())
    }

    fn sample_dummy_proof_bytes(has_plr_padding: bool) -> Vec<u8> {
        let mut rng = OsRng;

        let mut chain_nodes_flattened = vec![];
        let num_chain_nodes = rng.next_u32() % 5;
        for _ in 0..num_chain_nodes {
            let mut cn = [0u8; crate::hashwires::CHAIN_NODES_SIZE];
            rng.fill_bytes(&mut cn);
            chain_nodes_flattened.extend_from_slice(&cn[..]);
        }

        let mut mdp_salt = [0u8; crate::hashwires::MDP_SALT_SIZE];
        rng.fill_bytes(&mut mdp_salt);

        let mut smt_inclusion_proof = [0u8; 32];
        rng.fill_bytes(&mut smt_inclusion_proof);

        let mut bytes = [
            &serialize(&chain_nodes_flattened, 2),
            &mdp_salt.to_vec()[..],
            &serialize(&smt_inclusion_proof, 2),
        ]
        .concat();

        if has_plr_padding {
            let mut plr_padding = [0u8; crate::hashwires::PLR_PADDING_SIZE];
            rng.fill_bytes(&mut plr_padding);
            bytes.extend_from_slice(&plr_padding[..]);
        }

        bytes
    }

    #[test]
    fn test_proof_serialization_with_padding() -> Result<(), HWError> {
        let bytes = sample_dummy_proof_bytes(true);
        let proof = HWProof::deserialize(&bytes)?;
        let output = proof.serialize();

        assert_eq!(bytes.to_vec(), output);
        Ok(())
    }

    #[test]
    fn test_proof_serialization_without_padding() -> Result<(), HWError> {
        let bytes = sample_dummy_proof_bytes(false);
        let proof = HWProof::deserialize(&bytes)?;
        let output = proof.serialize();

        assert_eq!(bytes.to_vec(), output);
        Ok(())
    }
}
