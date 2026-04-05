use std::vec;

use ark_ff::{PrimeField, Zero};
use ark_poly::{
    DenseMVPolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain,
    multivariate::{SparsePolynomial, SparseTerm, Term},
    univariate::DensePolynomial,
};

use crate::{
    fri::prover::FriProof,
    polynomial::poly_pow,
    stark::air::{Air, BoundaryConstraint},
};

#[derive(Clone, Debug)]
pub struct StarkProof<F: PrimeField> {
    pub fri_proof: FriProof<F>,
    pub trace_evaluations: Vec<F>,
    pub trace_roots: Vec<F>,
}

fn interpolate_trace<F: PrimeField>(trace: &[Vec<F>]) -> Vec<DensePolynomial<F>> {
    let trace_length = trace.len();
    let domain = <GeneralEvaluationDomain<F> as EvaluationDomain<F>>::new(trace_length).unwrap();

    let num_registers = trace[0].len();
    let mut trace_polys = Vec::with_capacity(num_registers);

    for j in 0..num_registers {
        let column: Vec<F> = trace.iter().map(|row| row[j]).collect();
        let evals = Evaluations::from_vec_and_domain(column, domain);
        trace_polys.push(evals.interpolate());
    }

    trace_polys
}

fn boundary_quotients<F: PrimeField>(
    trace_polys: &[DensePolynomial<F>],
    boundary_constraints: &[BoundaryConstraint<F>],
    domain: &GeneralEvaluationDomain<F>,
) -> Vec<DensePolynomial<F>> {
    let mut polys = Vec::with_capacity(boundary_constraints.len());

    for constraint in boundary_constraints {
        let t_poly = &trace_polys[constraint.register];
        let numerator = t_poly - DensePolynomial::from_coefficients_vec(vec![constraint.value]);
        let omega_c = domain.element(constraint.cycle);
        let denominator = DensePolynomial::from_coefficients_vec(vec![-omega_c, F::one()]);
        let poly = numerator / denominator;

        polys.push(poly);
    }

    polys
}

fn transition_quotients<F: PrimeField>(
    trace_polys: &[DensePolynomial<F>],
    transition_constraints: &[SparsePolynomial<F, SparseTerm>],
    domain: &GeneralEvaluationDomain<F>,
) -> Vec<DensePolynomial<F>> {
    let t = domain.size();
    let omega = domain.group_gen();
    let w = trace_polys.len();

    let mut polys = Vec::with_capacity(transition_constraints.len());
    let mut shifted_polys = Vec::with_capacity(transition_constraints.len());

    for trace_poly in trace_polys {
        let mut shifted_coeffs = Vec::with_capacity(trace_poly.coeffs.len());
        for (i, coeff) in trace_poly.coeffs.iter().enumerate() {
            shifted_coeffs.push(*coeff * omega.pow(vec![i as u64]));
        }
        shifted_polys.push(DensePolynomial::from_coefficients_vec(shifted_coeffs));
    }

    let vanishing: DensePolynomial<F> = domain.vanishing_polynomial().into();
    let last_point = domain.element(t - 1);
    let exclude_last = DensePolynomial::from_coefficients_vec(vec![-last_point, F::one()]);
    let transition_zerofier = vanishing / exclude_last;

    for constraint in transition_constraints {
        let mut numerator = DensePolynomial::<F>::zero();
        for (coeff, term) in constraint.terms() {
            let mut mononial = DensePolynomial::from_coefficients_vec(vec![*coeff]);
            for (var_index, power) in term.vars().iter().zip(term.powers()) {
                let p = if *var_index < w {
                    poly_pow(&trace_polys[*var_index], power)
                } else {
                    poly_pow(&shifted_polys[*var_index - w], power)
                };
                mononial = mononial * p;
            }
            numerator = numerator + mononial;
        }

        let poly = numerator / transition_zerofier.clone();
        polys.push(poly);
    }

    polys
}

pub fn prove<F: PrimeField>(trace: Vec<Vec<F>>, air: &Air<F>) -> StarkProof<F> {
    // 1. Interpolate trace → trace_polys
    // 2. Compute boundary quotients
    // 3. Compute transition quotients
    // 4. Get random weights from Fiat-Shamir transcript
    // 5. Combine: composition = Σ weight_i · quotient_i
    // 6. Run FRI on the composition polynomial
    // 7. Package everything into StarkProof
    todo!()
}
