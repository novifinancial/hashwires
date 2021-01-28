# HashWires ![Build Status](https://github.com/novifinancial/hashwires/workflows/Rust%20CI/badge.svg)

HashWires is a hash-based range proof protocol that is applicable in settings for which there is a trusted thirdparty (typically a credential issuer) that can generate commitments. We refer to these as "credential-based" range proofs.

HashWires improves upon hash chain solutions that are typically restricted to micropayments for small interval ranges, achieving an exponential speedup in proof generation and verification time. In terms of proof size, we also show that HashWires compares favorably against Bulletproofs for both 32- and 64-bit numeric values. Although credential-based range proofs are inherently less flexible than general range proofs, we provide a number of applications in which a credential  issuer can leverage HashWires to provide range proofs for private values, without having to rely on heavyweight cryptographic tools and assumptions.
