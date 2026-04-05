pub mod air;
pub mod prover;
pub mod verifier;

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use ark_poly::DenseMVPolynomial;
    use ark_poly::multivariate::{SparsePolynomial, SparseTerm, Term};

    use crate::field::Fq;
    use crate::stark::air::{Air, BoundaryConstraint};
    use crate::stark::prover::prove;
    use crate::stark::verifier::verify;

    fn repeated_squaring_air<F: PrimeField>(trace_length: usize, input: F, output: F) -> Air<F> {
        let transition = SparsePolynomial::from_coefficients_vec(
            2, // 2 variables: x_0 (current), x_1 (next)
            vec![
                (F::one(), SparseTerm::new(vec![(1, 1)])),  // + x_1
                (-F::one(), SparseTerm::new(vec![(0, 2)])), // - x_0²
            ],
        );

        Air {
            num_registers: 1,
            original_trace_length: trace_length,
            transition_constraints: vec![transition],
            boundary_constraints: vec![
                BoundaryConstraint {
                    cycle: 0,
                    register: 0,
                    value: input,
                },
                BoundaryConstraint {
                    cycle: trace_length - 1,
                    register: 0,
                    value: output,
                },
            ],
        }
    }
    #[test]
    fn test_stark_repeated_squaring() {
        // Prove: starting from x=3, apply x→x² four times
        let input = Fq::from(3);
        let trace_length = 4;

        // Build the execution trace
        let mut trace = vec![vec![input]];
        for i in 1..trace_length {
            let prev = trace[i - 1][0];
            trace.push(vec![prev * prev]);
        }
        // trace = [[3], [9], [81], [6561]]

        let output = trace[trace_length - 1][0];
        let air = repeated_squaring_air(trace_length, input, output);

        let proof = prove(trace, &air);
        assert!(verify(&proof, &air).is_ok());
    }

    #[test]
    fn test_stark_soundness() {
        let input = Fq::from(3);
        let trace_length = 4;

        let mut trace = vec![vec![input]];
        for i in 1..trace_length {
            let prev = trace[i - 1][0];
            trace.push(vec![prev * prev]);
        }

        let output = trace[trace_length - 1][0];
        let air = repeated_squaring_air(trace_length, input, output);

        // Tamper with the trace
        trace[2][0] += Fq::from(1);

        let proof = prove(trace, &air);
        assert!(verify(&proof, &air).is_err());
    }
}
