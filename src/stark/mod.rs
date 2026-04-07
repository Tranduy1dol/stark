pub mod air;
pub mod domain;
pub mod prover;
mod quotient;
pub mod verifier;

#[cfg(test)]
mod tests {
    use ark_ff::{PrimeField, Zero};
    use ark_poly::DenseMVPolynomial;
    use ark_poly::multivariate::{SparsePolynomial, SparseTerm, Term};

    use crate::crypto::transcript::Transcript;
    use crate::field::Fq;
    use crate::stark::air::{Air, BoundaryConstraint};
    use crate::stark::prover::{prove, prove_fast};
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
        let input = Fq::from(3);
        let trace_length = 4;

        let mut trace = vec![vec![input]];
        for i in 1..trace_length {
            let prev = trace[i - 1][0];
            trace.push(vec![prev * prev]);
        }

        let output = trace[trace_length - 1][0];
        let air = repeated_squaring_air(trace_length, input, output);

        let mut prover_transcript = Transcript::new(Fq::zero());
        let proof = prove(trace, &air, &mut prover_transcript);

        let mut verifier_transcript = Transcript::new(Fq::zero());
        assert!(verify(&proof, &air, &mut verifier_transcript).is_ok());
    }

    #[test]
    fn test_stark_fast_repeated_squaring() {
        let input = Fq::from(3);
        let trace_length = 4;

        let mut trace = vec![vec![input]];
        for i in 1..trace_length {
            let prev = trace[i - 1][0];
            trace.push(vec![prev * prev]);
        }

        let output = trace[trace_length - 1][0];
        let air = repeated_squaring_air(trace_length, input, output);

        let mut prover_transcript = Transcript::new(Fq::zero());
        let proof = prove_fast(trace, &air, 4, &mut prover_transcript);

        let mut verifier_transcript = Transcript::new(Fq::zero());
        assert!(verify(&proof, &air, &mut verifier_transcript).is_ok());
    }

    #[test]
    fn bench_naive_vs_fast() {
        use std::time::Instant;

        println!(
            "\n{:<15} {:>12} {:>12} {:>10}",
            "Trace Length", "Naive", "Fast", "Speedup"
        );
        println!("{:-<52}", "");

        for trace_length in [64, 256, 1024] {
            let input = Fq::from(3);

            let mut trace = vec![vec![input]];
            for i in 1..trace_length {
                let prev = trace[i - 1][0];
                trace.push(vec![prev * prev]);
            }

            let output = trace[trace_length - 1][0];
            let air = repeated_squaring_air(trace_length, input, output);

            let start = Instant::now();
            let mut transcript = Transcript::new(Fq::zero());
            let _proof_naive = prove(trace.clone(), &air, &mut transcript);
            let naive_time = start.elapsed();

            let start = Instant::now();
            let mut transcript = Transcript::new(Fq::zero());
            let _proof_fast = prove_fast(trace, &air, 4, &mut transcript);
            let fast_time = start.elapsed();

            println!(
                "{:<15} {:>12.2?} {:>12.2?} {:>9.1}x",
                trace_length,
                naive_time,
                fast_time,
                naive_time.as_secs_f64() / fast_time.as_secs_f64()
            );
        }
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

        let mut prover_transcript = Transcript::new(Fq::zero());
        let proof = prove(trace, &air, &mut prover_transcript);

        let mut verifier_transcript = Transcript::new(Fq::zero());
        assert!(verify(&proof, &air, &mut verifier_transcript).is_err());
    }
}
