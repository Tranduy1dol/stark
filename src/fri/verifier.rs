use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

use crate::{
    crypto::{merkle::verify_merkle_proof, transcript::Transcript},
    fri::prover::{Decommitment, FriProof},
};

pub fn verify<F: PrimeField>(proof: &FriProof<F>) -> anyhow::Result<()> {
    let mut transcript = Transcript::new(F::ZERO);
    let random_r_list: Vec<F> = proof
        .layers_root
        .iter()
        .map(|&root| {
            transcript.digest(root);
            transcript.generate_a_challenge()
        })
        .collect();
    transcript.digest(proof.const_val);
    let query_indices =
        transcript.generate_challenge_list_usize(proof.number_of_queries, proof.domain_size);

    for (query_idx, decommitment) in query_indices
        .into_iter()
        .zip(proof.decommitment_list.iter())
    {
        verify_single_query(
            query_idx,
            decommitment,
            &random_r_list,
            proof.domain_size,
            proof.coset,
            proof.const_val,
        )?;
    }

    Ok(())
}

fn verify_single_query<F: PrimeField>(
    query_idx: usize,
    decommitment: &Decommitment<F>,
    random_r_list: &[F],
    domain_size: usize,
    coset: F,
    const_val: F,
) -> anyhow::Result<()> {
    let mut curr_idx = query_idx;
    let mut curr_coset = coset;
    let mut curr_domain_size = domain_size;

    let num_layers = random_r_list.len();
    let two = F::from(2u64);

    for (layer_i, &r) in random_r_list.iter().enumerate() {
        let sym_idx = (curr_idx + curr_domain_size / 2) % curr_domain_size;

        // Verify Merkle proofs
        if !verify_merkle_proof(&decommitment.auth_paths[layer_i]) {
            return Err(anyhow::anyhow!("Merkle proof invalid at layer {layer_i}"));
        }
        if !verify_merkle_proof(&decommitment.sym_auth_paths[layer_i]) {
            return Err(anyhow::anyhow!(
                "Symmetric Merkle proof invalid at layer {layer_i}"
            ));
        }

        // Verify indices match
        if decommitment.auth_paths[layer_i].index != curr_idx
            || decommitment.sym_auth_paths[layer_i].index != sym_idx
        {
            return Err(anyhow::anyhow!("Wrong index at layer {layer_i}"));
        }

        let f_x = decommitment.evaluations[layer_i];
        let f_neg_x = decommitment.sym_evaluations[layer_i];

        let domain =
            <GeneralEvaluationDomain<F> as EvaluationDomain<F>>::new(curr_domain_size).unwrap();
        let w = domain.element(curr_idx) * curr_coset;
        let folded = (f_x + f_neg_x) / two + r * (f_x - f_neg_x) / (two * w);

        // Check folded value against next layer or const_val
        if layer_i == num_layers - 1 {
            if folded != const_val {
                return Err(anyhow::anyhow!("Final folded value != const_val"));
            }
        } else if folded != decommitment.evaluations[layer_i + 1] {
            return Err(anyhow::anyhow!("Folding mismatch at layer {layer_i}"));
        }

        curr_domain_size /= 2;
        curr_idx %= curr_domain_size;
        curr_coset = curr_coset.square();
    }

    Ok(())
}
