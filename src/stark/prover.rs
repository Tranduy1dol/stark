use std::vec;

use ark_ff::{PrimeField, Zero};
use ark_poly::{
    DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, univariate::DensePolynomial,
};

use crate::{
    crypto::{merkle::MerkleTree, transcript::Transcript},
    fri::{
        layer::FriLayer,
        prover::{FriProof, generate_proof},
    },
    polynomial::{domain, shift_poly},
    stark::{air::Air, domain::PreprocessedDomain},
};

use super::quotient::*;

#[derive(Clone, Debug)]
pub struct StarkProof<F: PrimeField> {
    pub fri_proof: FriProof<F>,
    pub trace_roots: Vec<F>,
    pub trace_evals_at_z: Vec<F>,
    pub trace_evals_at_omega_z: Vec<F>,
    pub composition_eval_at_z: F,
}

pub fn prove_fast<F: PrimeField>(
    trace: Vec<Vec<F>>,
    air: &Air<F>,
    blowup_factor: usize,
    transcript: &mut Transcript<F>,
) -> StarkProof<F> {
    let t = trace.len();
    let num_queries = 16;
    let preprocessed = PreprocessedDomain::<F>::new(air.original_trace_length, blowup_factor);

    let trace_domain = preprocessed.trace_domain;
    let eval_domain = preprocessed.eval_domain;
    let e = eval_domain.size();
    let w = air.num_registers;
    let omega = trace_domain.group_gen();

    let coset = F::GENERATOR;
    let trace_polys = interpolate_trace(&trace);

    let mut trace_evals = Vec::with_capacity(w);
    for trace_poly in &trace_polys {
        let shifted = shift_poly(trace_poly, coset);
        let evals = eval_domain.fft(&shifted.coeffs);
        trace_evals.push(evals);
    }

    let mut shifted_evals = Vec::with_capacity(w);
    for trace_poly in &trace_polys {
        let shifted = shift_poly(trace_poly, omega * coset);
        let evals = eval_domain.fft(&shifted.coeffs);
        shifted_evals.push(evals);
    }

    let mut trace_roots = Vec::with_capacity(w);
    for eval in trace_evals.clone() {
        let tree = MerkleTree::new(eval);
        let root = tree.root();
        trace_roots.push(root);
        transcript.digest(root);
    }

    let z = transcript.generate_a_challenge();
    let mut trace_evals_at_z = Vec::new();
    let mut trace_evals_at_omega_z = Vec::new();

    for trace_poly in &trace_polys {
        trace_evals_at_z.push(trace_poly.evaluate(&z));
        trace_evals_at_omega_z.push(trace_poly.evaluate(&(omega * z)));
    }
    for eval in &trace_evals_at_z {
        transcript.digest(*eval);
    }
    for eval in &trace_evals_at_omega_z {
        transcript.digest(*eval);
    }

    // Precompute eval points: x_j = coset · η^j
    let eval_points = eval_domain
        .elements()
        .map(|eta| coset * eta)
        .collect::<Vec<_>>();

    let mut boundary_quotient_evals_list = Vec::new();
    for constraint in &air.boundary_constraints {
        let omega_c = trace_domain.element(constraint.cycle);
        let mut q_evals = Vec::with_capacity(e);
        for j in 0..e {
            let num = trace_evals[constraint.register][j] - constraint.value;
            let den = eval_points[j] - omega_c;
            q_evals.push(num / den);
        }
        boundary_quotient_evals_list.push(q_evals);
    }

    let last_point = trace_domain.element(t - 1);
    let mut transition_zerofier_evals = Vec::with_capacity(e);
    for eval_point in eval_points.iter().take(e) {
        let vanishing_val = eval_point.pow([t as u64]) - F::one(); // x^T - 1
        let tz = vanishing_val / (*eval_point - last_point);
        transition_zerofier_evals.push(tz);
    }

    let mut transition_quotient_evals_list = Vec::new();
    for constraint in &air.transition_constraints {
        let mut q_evals = Vec::new();
        for j in 0..e {
            let mut point = Vec::new();

            for trace_eval in trace_evals.iter().take(w) {
                point.push(trace_eval[j]);
            }
            for shifted_eval in shifted_evals.iter().take(w) {
                point.push(shifted_eval[j]);
            }

            let num = constraint.evaluate(&point);
            q_evals.push(num / transition_zerofier_evals[j]);
        }
        transition_quotient_evals_list.push(q_evals);
    }

    let mut all_quotients_evals = boundary_quotient_evals_list.clone();
    all_quotients_evals.extend(transition_quotient_evals_list);

    let mut composition_evals = vec![F::zero(); e];
    for q_evals in all_quotients_evals {
        let weight = transcript.generate_a_challenge();
        for j in 0..e {
            composition_evals[j] += weight * q_evals[j];
        }
    }

    let coset_poly = Evaluations::from_vec_and_domain(composition_evals, eval_domain).interpolate();
    let coset_inv = coset.inverse().expect("coset must be invertible");
    let composition = shift_poly(&coset_poly, coset_inv);
    let composition_eval_at_z = composition.evaluate(&z);
    transcript.digest(composition_eval_at_z);

    let fri_proof = generate_proof(composition, blowup_factor, num_queries, transcript);

    StarkProof {
        fri_proof,
        trace_evals_at_z,
        trace_evals_at_omega_z,
        trace_roots,
        composition_eval_at_z,
    }
}

pub fn prove<F: PrimeField>(
    trace: Vec<Vec<F>>,
    air: &Air<F>,
    transcript: &mut Transcript<F>,
) -> StarkProof<F> {
    let t = trace.len();
    let blowup_factor = 4;
    let num_queries = 16;

    let domain = domain(t);
    let omega = domain.group_gen();
    let trace_polys = interpolate_trace(&trace);

    let mut trace_roots = Vec::with_capacity(t);
    for trace_poly in trace_polys.clone() {
        let fri_layer = FriLayer::from_poly(&trace_poly, F::GENERATOR, t * blowup_factor);
        let root = fri_layer.merkle_tree.root();

        trace_roots.push(root);
        transcript.digest(root);
    }

    let z = transcript.generate_a_challenge();
    let mut trace_evals_at_z = Vec::new();
    let mut trace_evals_at_omega_z = Vec::new();

    for trace_poly in &trace_polys {
        trace_evals_at_z.push(trace_poly.evaluate(&z));
        trace_evals_at_omega_z.push(trace_poly.evaluate(&(omega * z)));
    }
    for eval in &trace_evals_at_z {
        transcript.digest(*eval);
    }
    for eval in &trace_evals_at_omega_z {
        transcript.digest(*eval);
    }

    let mut all_quotients = boundary_quotients(&trace_polys, &air.boundary_constraints, &domain);
    let t_quotients = transition_quotients(&trace_polys, &air.transition_constraints, &domain);
    all_quotients.extend(t_quotients);

    let mut composition = DensePolynomial::zero();
    for quotient in all_quotients {
        let weight = transcript.generate_a_challenge();
        composition = composition + quotient * DensePolynomial::from_coefficients_vec(vec![weight]);
    }

    let composition_eval_at_z = composition.evaluate(&z);
    transcript.digest(composition_eval_at_z);

    let fri_proof = generate_proof(composition, blowup_factor, num_queries, transcript);

    StarkProof {
        fri_proof,
        trace_evals_at_z,
        trace_evals_at_omega_z,
        trace_roots,
        composition_eval_at_z,
    }
}
