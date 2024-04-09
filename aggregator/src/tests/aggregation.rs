use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use ethers_core::utils::keccak256;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, poly::commitment::Params};
use itertools::Itertools;
use primitive_types::{H384, U256};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};

use crate::{
    aggregation::AggregationCircuit, batch::BatchHash, chunk, constants::MAX_AGG_SNARKS, layer_0,
    tests::mock_chunk::MockChunkCircuit, ChunkHash,
};

#[test]
fn test_aggregation_circuit() {
    env_logger::init();

    let k = 20;

    // This set up requires one round of keccak for chunk's data hash
    let circuit = build_new_aggregation_circuit(2);
    let instance = circuit.instances();
    let mock_prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    mock_prover.assert_satisfied_par();
}

#[ignore = "it takes too much time"]
#[test]
fn test_aggregation_circuit_all_possible_num_snarks() {
    env_logger::init();

    let k = 20;

    for i in 1..=MAX_AGG_SNARKS {
        println!("{i} real chunks and {} padded chunks", MAX_AGG_SNARKS - i);
        // This set up requires one round of keccak for chunk's data hash
        let circuit = build_new_aggregation_circuit(i);
        let instance = circuit.instances();
        let mock_prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        mock_prover.assert_satisfied_par();
    }
}

/// - Test aggregation proof generation and verification.
/// - Test a same pk can be used for various number of chunk proofs.
#[ignore = "it takes too much time"]
#[test]
fn test_aggregation_circuit_full() {
    env_logger::init();
    let process_id = process::id();

    let dir = format!("data/{process_id}",);
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    // This set up requires one round of keccak for chunk's data hash
    let circuit = build_new_aggregation_circuit(2);
    let instance = circuit.instances();
    let mock_prover = MockProver::<Fr>::run(25, &circuit, instance).unwrap();
    mock_prover.assert_satisfied_par();

    log::trace!("finished mock proving");

    let mut rng = test_rng();
    let param = gen_srs(20);

    let pk = gen_pk(&param, &circuit, None);
    log::trace!("finished pk generation for circuit");

    let snark = gen_snark_shplonk(&param, &pk, circuit.clone(), &mut rng, None::<String>);
    log::trace!("finished snark generation for circuit");

    assert!(verify_snark_shplonk::<AggregationCircuit>(
        &param,
        snark,
        pk.get_vk()
    ));
    log::trace!("finished verification for circuit");

    // This set up requires two rounds of keccak for chunk's data hash
    let circuit = build_new_aggregation_circuit(5);
    let snark = gen_snark_shplonk(&param, &pk, circuit, &mut rng, None::<String>);
    log::trace!("finished snark generation for circuit");

    assert!(verify_snark_shplonk::<AggregationCircuit>(
        &param,
        snark,
        pk.get_vk()
    ));
    log::trace!("finished verification for circuit");
}

fn build_new_aggregation_circuit(num_real_chunks: usize) -> AggregationCircuit {
    // inner circuit: Mock circuit
    let k0 = 8;

    let mut rng = test_rng();
    let params = gen_srs(k0);
    let batch_commit_bytes = [0u8; 48];
    let batch_commit = H384::from_slice(batch_commit_bytes.as_slice());
    let mut chunks_without_padding = (0..num_real_chunks)
        .map(|_| ChunkHash::mock_random_chunk_hash_for_testing(&mut rng))
        .collect_vec();
    for i in 0..num_real_chunks - 1 {
        chunks_without_padding[i + 1].prev_state_root = chunks_without_padding[i].post_state_root;
    }

    //modify chunk challenge point for test
    let preimage = chunks_without_padding
        .iter()
        .flat_map(|chunk_hash| chunk_hash.data_hash.0.iter())
        .cloned()
        .collect::<Vec<_>>();
    let batch_data_hash = keccak256(preimage);
    let cp_preimage = [batch_commit.0.as_slice(), batch_data_hash.as_slice()].concat();
    let mut challenge_point = keccak256(cp_preimage);

    challenge_point[31] = 0;

    for chunk_hash in chunks_without_padding.iter_mut() {
        chunk_hash.challenge_point = U256::from_little_endian(&challenge_point);
    }

    let padded_chunk =
        ChunkHash::mock_padded_chunk_hash_for_testing(&chunks_without_padding[num_real_chunks - 1]);
    let chunks_with_padding = [
        chunks_without_padding,
        vec![padded_chunk; MAX_AGG_SNARKS - num_real_chunks],
    ]
    .concat();

    // ==========================
    // real chunks
    // ==========================
    let real_snarks = {
        let circuits = chunks_with_padding
            .iter()
            .take(num_real_chunks)
            .map(|&chunk| MockChunkCircuit::new(true, chunk))
            .collect_vec();
        circuits
            .iter()
            .map(|&circuit| layer_0!(circuit, MockChunkCircuit, params, k0, path))
            .collect_vec()
    };

    // ==========================
    // padded chunks
    // ==========================
    let padded_snarks =
        { vec![real_snarks.last().unwrap().clone(); MAX_AGG_SNARKS - num_real_chunks] };

    // ==========================
    // batch
    // ==========================
    let batch_hash = BatchHash::construct(&chunks_with_padding, batch_commit);

    AggregationCircuit::new(
        &params,
        [real_snarks, padded_snarks].concat().as_ref(),
        rng,
        batch_hash,
    )
    .unwrap()
}
