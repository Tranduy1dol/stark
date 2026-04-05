pub mod layer;
pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests {
    use crate::field::Fq;
    use crate::fri::prover::generate_proof;
    use crate::fri::verifier::verify;
    use ark_poly::DenseUVPolynomial;
    use ark_poly::univariate::DensePolynomial;

    #[test]
    fn test_fri_roundtrip_degree_3() {
        let poly = DensePolynomial::from_coefficients_vec(vec![
            Fq::from(1),
            Fq::from(2),
            Fq::from(3),
            Fq::from(4),
        ]);
        let proof = generate_proof(poly, 2, 2); // blowup=2, queries=2
        assert!(verify(&proof).is_ok());
    }

    #[test]
    fn test_fri_roundtrip_degree_5() {
        let poly = DensePolynomial::from_coefficients_vec(vec![
            Fq::from(1),
            Fq::from(2),
            Fq::from(3),
            Fq::from(4),
            Fq::from(5),
            Fq::from(6),
        ]);
        let proof = generate_proof(poly, 2, 2);
        assert!(verify(&proof).is_ok());
    }

    #[test]
    fn test_fri_soundness() {
        let poly = DensePolynomial::from_coefficients_vec(vec![
            Fq::from(1),
            Fq::from(2),
            Fq::from(3),
            Fq::from(4),
        ]);
        let mut proof = generate_proof(poly, 2, 2);
        proof.const_val -= Fq::from(1); // tamper!
        assert!(verify(&proof).is_err());
    }
}
