use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Polynomial};

use crate::{
    crypto::transcript::Transcript,
    polynomial::domain,
    stark::{air::Air, prover::StarkProof},
};

pub fn verify<F: PrimeField>(
    proof: &StarkProof<F>,
    air: &Air<F>,
    transcript: &mut Transcript<F>,
) -> anyhow::Result<()> {
    let t = air.original_trace_length;
    let domain = domain::<F>(t);

    let num_boundary = air.boundary_constraints.len();
    let num_transition = air.transition_constraints.len();

    for root in &proof.trace_roots {
        transcript.digest(*root);
    }

    let z = transcript.generate_a_challenge();
    for eval in &proof.trace_evals_at_z {
        transcript.digest(*eval);
    }
    for eval in &proof.trace_evals_at_omega_z {
        transcript.digest(*eval);
    }

    let mut boundary_quotient_values = Vec::with_capacity(num_boundary);
    for constraint in &air.boundary_constraints {
        let omega_c = domain.element(constraint.cycle);
        let q = (proof.trace_evals_at_z[constraint.register] - constraint.value) / (z - omega_c);
        boundary_quotient_values.push(q);
    }

    let mut transition_quotient_values = Vec::with_capacity(num_transition);
    let last = domain.element(t - 1);
    let zerofier_at_z = (z.pow(vec![t as u64]) - F::one()) / (z - last);
    for constraint in &air.transition_constraints {
        let mut point = proof.trace_evals_at_z.clone();
        point.extend(proof.trace_evals_at_omega_z.clone());

        let c_val = constraint.evaluate(&point);
        let q = c_val / zerofier_at_z;
        transition_quotient_values.push(q);
    }

    let mut all_q = boundary_quotient_values;
    all_q.extend(transition_quotient_values);
    let mut expected = F::zero();
    for q in all_q {
        let weight = transcript.generate_a_challenge();
        expected += weight * q;
    }

    transcript.digest(proof.composition_eval_at_z);
    if proof.composition_eval_at_z != expected {
        return Err(anyhow::anyhow!("composition mismatch"));
    }

    crate::fri::verifier::verify(&proof.fri_proof, transcript)?;

    Ok(())
}
