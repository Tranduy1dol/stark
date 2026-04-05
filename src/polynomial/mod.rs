use ark_ff::PrimeField;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};

pub fn poly_pow<F: PrimeField>(poly: &DensePolynomial<F>, exp: usize) -> DensePolynomial<F> {
    match exp {
        0 => DensePolynomial::from_coefficients_vec(vec![F::one()]),
        1 => poly.clone(),
        _ => {
            let mut result = poly.clone();
            for _ in 1..exp {
                result = &result * poly;
            }
            result
        }
    }
}
