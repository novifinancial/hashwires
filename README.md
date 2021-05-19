# HashWires :: Range proofs for issued credentials

A Rust implementation of the range proof scheme described in [HashWires: Hyperefficient Credential-Based Range Proofs](https://eprint.iacr.org/2021/297) 
by *Konstantinos Chalkias and Shir Cohen and Kevin Lewi and Fredric Moezinia and Yolan Romailler*. A more simplified 
demonstration of how HashWires work is available as a [ZKProof blogpost](https://zkproof.org/2021/05/05/hashwires-range-proofs-from-hash-functions/).

HashWires is a hash-based range proof protocol that is applicable in settings for which there is a trusted third party 
(typically a credential issuer) that can generate commitments. We refer to these as "credential-based" range proofs 
(CBRPs). It improves upon hashchain solutions that are typically restricted to micro-payments for small interval ranges,
achieving an exponential speedup in proof generation and verification time. In terms of proof size and computational 
cost, we show that HashWires compares favorably against Bulletproofs for both 32- and 64-bit numeric values. 

Although CBRPs are inherently less flexible than general zero-knowledge range proofs, we provide a number of 
applications in which a credential issuer can leverage HashWires to provide range proofs for private values, 
without having to rely on heavyweight cryptographic tools and assumptions.

## Potential Applications:
- KYC range proofs (e.g., older/younger than age proofs)
- 2D/3D location range proofs
- Proof of income (e.g., to landlords) without revealing the exact bank account balance or payslip salary
- Timestamp ranges (e.g, for digital certificates)
- Top % rankings (e.g., online contest ranking)
- % range for ingredients (e.g., in food and chemical products, showing compliance but without revealing the recipe
- Micro payments (e.g., gradually redeemable cashier checks)
- Auction systems, where bidders want to hide their available funds (as this leaks information on how far they can go)

Note: The commitments used in HashWires are not homomorphic and thus they cannot be used for adding confidential amounts 
in blockchain applications.

Documentation
-------------

Let's assume that Alice is a trusted issuer and Bob is requesting a HashWires commitment for his age (he is 43 years 
old). Carol is a verifier, who should be convinced that Bob is older that 21 years. They all agree on a `base: u32` 
which defines how long each hash-chain can be and `max_number_bits: usize` which denotes the bits of the maximum number 
supported in this use case.

Given Bob's age `value: BigUint`, Alice picks a `seed: [u8]` and instantiates a `Secret` for this commitment as 
`let secret = Secret::<Blake3>::gen(&seed, &value);`. The `secret` can be instantiated with any hash function (in 
this example we are using Blake3).

Alice can now generate a commitment by `let commitment = secret.commit(base, max_number_bits);`. Currently this crate 
can only support a `base` in the set of {2, 4, 16, 256}. If required, a commitment can be serialized using 
`let commitment_bytes = commitment.serialize();` and it will be provided to Bob (in practice signed by Alice's key).

Bob can now generate a range proof by `let proof = secret.prove(base, max_number_bits, &threshold);`, where 
`threshold: BigUint` is the challenge (range value) Carol is requesting (thus, 21 in our example).

Given the HashWires `commitment` and `proof`, Carol can verify the range proof's statement by 
`commitment.verify(&proof, &threshold);`, which will return a `HwError` if it fails.

Contributors
------------

The original authors of this code are Konstantinos Chalkias
([@kchalkias](https://github.com/kchalkias)), Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)) and Yolan Romailler ([@AnomalRoil](https://github.com/AnomalRoil)).
To learn more about contributing to this project, [see this document](./CONTRIBUTING.md).

License
-------

This project is [MIT licensed](./LICENSE).

[Terms of Use](https://opensource.facebook.com/legal/terms)

[Privacy Policy](https://opensource.facebook.com/legal/privacy)
