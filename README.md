# stark

A STARK (Scalable Transparent ARgument of Knowledge) implementation in Rust using the [arkworks](https://github.com/arkworks-rs) ecosystem, following [Anatomy of a STARK](https://aszepieniec.github.io/stark-anatomy/).

## Features

- **Goldilocks field** (`2^64 - 2^32 + 1`) via `ark-ff`
- **Cryptographic primitives** — SHA-256 hasher, Merkle tree, Fiat-Shamir transcript
- **FRI** (Fast Reed-Solomon IOP of Proximity) — polynomial folding, prover, verifier
- **STARK prover & verifier** — AIR constraints, boundary/transition quotients, FRI-based proof
- **Optimized prover** — NTT-based pointwise evaluation (coset FFT), no polynomial multiplication/division

## Benchmarks

Repeated squaring AIR (`x_{i+1} = x_i²`), blowup factor 4, 16 FRI queries. Release build:

| Trace Length | Naive Prover | Fast Prover | Speedup |
|:-------------|:-------------|:------------|:--------|
| 64           | 4.58ms       | 2.61ms      | 1.8x    |
| 256          | 11.22ms      | 9.83ms      | 1.1x    |
| 1024         | 101.92ms     | 77.98ms     | 1.3x    |

The fast prover avoids O(n²) polynomial multiplication by working entirely in evaluation space (pointwise operations + FFT). Speedup grows with trace size.

## Project Structure

```
src/
├── field/
│   ├── mod.rs
│   └── goldilocks.rs          # Goldilocks Fq via MontConfig
├── polynomial/
│   └── mod.rs                 # poly_pow, shift_poly, domain, FFT helpers
├── crypto/
│   ├── hasher.rs              # SHA-256 → field element
│   ├── merkle.rs              # MerkleTree<F> + MerkleProof<F>
│   └── transcript.rs          # Fiat-Shamir (absorb/squeeze)
├── fri/
│   ├── layer.rs               # FriLayer<F> — evaluations + Merkle commitment
│   ├── prover.rs              # fold_polynomial + generate_proof
│   └── verifier.rs            # verify FRI proof
└── stark/
    ├── air.rs                 # BoundaryConstraint, Air<F>
    ├── domain.rs              # PreprocessedDomain — cached domain data
    ├── quotient.rs            # boundary_quotients, transition_quotients
    ├── prover.rs              # prove (naive) + prove_fast (NTT-based)
    └── verifier.rs            # verify proof via FRI
```

## Usage

```bash
cargo build
cargo test
cargo test --release bench_naive_vs_fast -- --nocapture  # benchmarks
```

## Remaining Work

- [ ] **DEEP-ALI** — out-of-domain sampling for proper soundness (currently the verifier only checks FRI, so tampered traces aren't detected)
- [ ] **Shared transcript** — unify Fiat-Shamir transcript between STARK and FRI for tighter cryptographic binding
- [ ] **Parallelism** — `rayon` for pointwise constraint evaluation loops
- [ ] **Folding schemes** — Nova-style incremental verification
- [ ] **Lattice-based commitments** — replace hash-based Merkle with lattice assumptions
- [ ] **StarkVM** — define a VM instruction set as an AIR, prove arbitrary programs

## References

- [Anatomy of a STARK](https://aszepieniec.github.io/stark-anatomy/) — tutorial this implementation follows
- [arkworks](https://github.com/arkworks-rs) — finite field and polynomial library
- [sota-zk-labs/zkp-implementation](https://github.com/sota-zk-labs/zkp-implementation) — reference implementation

## License

This project is licensed under the MIT License.
