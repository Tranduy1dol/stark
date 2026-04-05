use ark_ff::PrimeField;

use crate::{
    crypto::transcript::Transcript,
    stark::{air::Air, prover::StarkProof},
};

pub fn verify<F: PrimeField>(proof: &StarkProof<F>, air: &Air<F>) -> anyhow::Result<()> {
    let mut transcript = Transcript::new(F::zero());
    for root in &proof.trace_roots {
        transcript.digest(*root);
    }

    let num_boundary = air.boundary_constraints.len();
    let num_transition = air.transition_constraints.len();
    let total_quotients = num_boundary + num_transition;

    let mut weight = Vec::with_capacity(total_quotients);
    for _ in 0..total_quotients {
        weight.push(transcript.generate_a_challenge());
    }

    crate::fri::verifier::verify(&proof.fri_proof)?;

    Ok(())
}
