use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, Region, Value},
    halo2curves::{
        bn256::{Bn256, Fq, Fr, G1Affine, G2Affine},
        pairing::Engine,
    },
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::{
        halo2::halo2_ecc::halo2_base::{self, AssignedValue},
        native::NativeLoader,
    },
    pcs::{
        kzg::{Bdfg21, Kzg, KzgAccumulator, KzgAs},
        AccumulationSchemeProver,
    },
    util::arithmetic::fe_to_limbs,
    verifier::PlonkVerifier,
    Error,
};
use snark_verifier_sdk::{
    types::{PoseidonTranscript, Shplonk, POSEIDON_SPEC},
    Snark,
};
use zkevm_circuits::{
    keccak_circuit::{
        keccak_packed_multi::{self, multi_keccak},
        KeccakCircuit, KeccakCircuitConfig,
    },
    table::{KeccakTable, LookupTable},
    util::Challenges,
};

use crate::{
    constants::{
        BATCH_CHALLENGE_POINT_INDEX, BATCH_COMMIT_INDEX, BATCH_RESULT_INDEX, CHAIN_ID_LEN,
        CHALLENGE_POINT_INDEX, DIGEST_LEN, INPUT_LEN_PER_ROUND, LOG_DEGREE, MAX_AGG_SNARKS,
        RESULT_INDEX,
    },
    util::{
        assert_conditional_equal, assert_equal, assert_equal_value, assert_exist, get_indices,
        get_max_keccak_updates, parse_hash_digest_cells, parse_hash_preimage_cells,
        parse_pi_hash_rlc_cells,
    },
    AggregationConfig, RlcConfig, BITS, CHUNK_DATA_HASH_INDEX, LIMBS, POST_STATE_ROOT_INDEX,
    PREV_STATE_ROOT_INDEX, WITHDRAW_ROOT_INDEX,
};

/// Subroutine for the witness generations.
/// Extract the accumulator and proof that from previous snarks.
/// Uses SHPlonk for accumulation.
pub(crate) fn extract_accumulators_and_proof(
    params: &ParamsKZG<Bn256>,
    snarks: &[Snark],
    rng: impl Rng + Send,
    g2: &G2Affine,
    s_g2: &G2Affine,
) -> Result<(KzgAccumulator<G1Affine, NativeLoader>, Vec<u8>), Error> {
    let svk = params.get_g()[0].into();

    let mut transcript_read =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&[], POSEIDON_SPEC.clone());
    let accumulators = snarks
        .iter()
        .flat_map(|snark| {
            transcript_read.new_stream(snark.proof.as_slice());
            let proof = Shplonk::read_proof(
                &svk,
                &snark.protocol,
                &snark.instances,
                &mut transcript_read,
            );
            // each accumulator has (lhs, rhs) based on Shplonk
            // lhs and rhs are EC points
            Shplonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof)
        })
        .collect::<Vec<_>>();
    // sanity check on the accumulator
    {
        for (i, acc) in accumulators.iter().enumerate() {
            let KzgAccumulator { lhs, rhs } = acc;
            let left = Bn256::pairing(lhs, g2);
            let right = Bn256::pairing(rhs, s_g2);
            log::trace!("acc extraction {}-th acc check: left {:?}", i, left);
            log::trace!("acc extraction {}-th acc check: right {:?}", i, right);
            if left != right {
                return Err(snark_verifier::Error::AssertionFailure(format!(
                    "accumulator check failed {left:?} {right:?}, index {i}",
                )));
            }
            //assert_eq!(left, right, "accumulator check failed");
        }
    }

    let mut transcript_write =
        PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
    // We always use SHPLONK for accumulation scheme when aggregating proofs
    let accumulator =
        // core step
        // KzgAs does KZG accumulation scheme based on given accumulators and random number (for adding blinding)
        // accumulated ec_pt = ec_pt_1 * 1 + ec_pt_2 * r + ... + ec_pt_n * r^{n-1}
        // ec_pt can be lhs and rhs
        // r is the challenge squeezed from proof
        KzgAs::<Kzg<Bn256, Bdfg21>>::create_proof::<PoseidonTranscript<NativeLoader, Vec<u8>>, _>(
            &Default::default(),
            &accumulators,
            &mut transcript_write,
            rng,
        )?;
    Ok((accumulator, transcript_write.finalize()))
}

/// Subroutine for the witness generations.
/// Extract proof from previous snarks and check pairing for accumulation.
pub fn extract_proof_and_instances_with_pairing_check(
    params: &ParamsKZG<Bn256>,
    snarks: &[Snark],
    rng: impl Rng + Send,
) -> Result<(Vec<u8>, Vec<Fr>), snark_verifier::Error> {
    // (old_accumulator, public inputs) -> (new_accumulator, public inputs)
    let (accumulator, as_proof) =
        extract_accumulators_and_proof(params, snarks, rng, &params.g2(), &params.s_g2())?;

    // the instance for the outer circuit is
    // - new accumulator, consists of 12 elements
    // - inner circuit's instance, flattened (old accumulator is stripped out if exists)
    //
    // it is important that new accumulator is the first 12 elements
    // as specified in CircuitExt::accumulator_indices()
    let KzgAccumulator::<G1Affine, NativeLoader> { lhs, rhs } = accumulator;

    // sanity check on the accumulator
    {
        let left = Bn256::pairing(&lhs, &params.g2());
        let right = Bn256::pairing(&rhs, &params.s_g2());
        log::trace!("circuit acc check: left {:?}", left);
        log::trace!("circuit acc check: right {:?}", right);

        if left != right {
            return Err(snark_verifier::Error::AssertionFailure(format!(
                "accumulator check failed {left:?} {right:?}",
            )));
        }
    }

    let acc_instances = [lhs.x, lhs.y, rhs.x, rhs.y]
        .map(fe_to_limbs::<Fq, Fr, { LIMBS }, { BITS }>)
        .concat();

    Ok((as_proof, acc_instances))
}

#[derive(Default)]
pub(crate) struct ExtractedHashCells {
    hash_input_cells: Vec<AssignedCell<Fr, Fr>>,
    hash_output_cells: Vec<AssignedCell<Fr, Fr>>,
    data_rlc_cells: Vec<AssignedCell<Fr, Fr>>,
    hash_input_len_cells: Vec<AssignedCell<Fr, Fr>>,
    is_final_cells: Vec<AssignedCell<Fr, Fr>>,
}

/// Input the hash input bytes,
/// assign the circuit for the hash function,
/// return
/// - cells of the hash digests
//
// This function asserts the following constraints on the hashes
//
// 1. batch_data_hash digest is reused for public input hash
// 2. batch_pi_hash used same roots as chunk_pi_hash
// 2.1. batch_pi_hash and chunk[0] use a same prev_state_root
// 2.2. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same post_state_root
// 2.3. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same withdraw_root
// 2.4. batch_pi_hash use same challenge point and result
// 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded
// 4. chunks are continuous: they are linked via the state roots
// 5. batch and all its chunks use a same chain id
// 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when chunk[i] is
// padded
// 7. the hash input length are correct
// - first MAX_AGG_SNARKS + 1 hashes all have 136 bytes input
// - batch's data_hash length is 32 * number_of_valid_snarks
// 8. batch data hash is correct w.r.t. its RLCs
// 9. is_final_cells are set correctly
// new. challenge_point and batch_pi_hash use same batch_commit and data_hash.
pub(crate) fn assign_batch_hashes(
    config: &AggregationConfig,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    chunks_are_valid: &[bool],
    preimages: &[Vec<u8>],
    assigned_result: &[AssignedValue<Fr>],
) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
    let extracted_hash_cells = extract_hash_cells(
        &config.keccak_circuit_config,
        layouter,
        challenges,
        preimages,
    )?;

    // 2. batch_pi_hash used same roots as chunk_pi_hash
    // 2.1. batch_pi_hash and chunk[0] use a same prev_state_root
    // 2.2. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same post_state_root
    // 2.3. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same withdraw_root
    // 5. batch and all its chunks use a same chain id
    copy_constraints(layouter, &extracted_hash_cells.hash_input_cells)?;

    // 1. batch_data_hash digest is reused for public input hash
    // 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not
    // padded
    // 4. chunks are continuous: they are linked via the state roots
    // 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when chunk[i] is
    // padded
    // 7. the hash input length are correct
    // - first MAX_AGG_SNARKS + 1 hashes all have 136 bytes input
    // - batch's data_hash length is 32 * number_of_valid_snarks
    // 8. batch data hash is correct w.r.t. its RLCs
    // 9. is_final_cells are set correctly
    conditional_constraints(
        &config.rlc_config,
        layouter,
        challenges,
        chunks_are_valid,
        &extracted_hash_cells,
        assigned_result,
    )?;

    Ok(extracted_hash_cells.hash_output_cells)
}

pub(crate) fn extract_hash_cells(
    keccak_config: &KeccakCircuitConfig<Fr>,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    preimages: &[Vec<u8>],
) -> Result<ExtractedHashCells, Error> {
    let mut is_first_time = true;
    let keccak_capacity = KeccakCircuit::<Fr>::capacity_for_row(1 << LOG_DEGREE);
    let max_keccak_updates = get_max_keccak_updates(MAX_AGG_SNARKS);
    let keccak_f_rows = keccak_packed_multi::get_num_rows_per_update();

    let timer = start_timer!(|| ("multi keccak").to_string());
    // preimages consists of the following parts
    // (1) batchPiHash preimage =
    //      (chain_id ||
    //      chunk[0].prev_state_root ||
    //      chunk[k-1].post_state_root ||
    //      chunk[k-1].withdraw_root ||
    //      batch_data_hash ||
    //      batch_commit ||
    //      challenge_point ||
    //      result)
    // challenge_point_hash preimage =
    //      (batch_commit || batch_data_hash)
    // (2) chunk[i].piHash preimage =
    //      (chain id ||
    //      chunk[i].prevStateRoot || chunk[i].postStateRoot ||
    //      chunk[i].withdrawRoot || chunk[i].datahash
    //      challenge_point ||
    //      result)
    // (3) batchDataHash preimage =
    //      (chunk[0].dataHash || ... || chunk[k-1].dataHash)
    // each part of the preimage is mapped to image by Keccak256
    let witness = multi_keccak(preimages, challenges, keccak_capacity)
        .map_err(|e| Error::AssertionFailure(format!("multi keccak assignment failed: {e:?}")))?;
    end_timer!(timer);

    // extract the indices of the rows for which the preimage and the digest cells lie in
    let (preimage_indices, digest_indices) = get_indices(preimages);

    let extracted_hash_cells = layouter
        .assign_region(
            || "assign keccak rows",
            |mut region| -> Result<ExtractedHashCells, halo2_proofs::plonk::Error> {
                if is_first_time {
                    is_first_time = false;
                    let offset = witness.len() - 1;
                    keccak_config.set_row(&mut region, offset, &witness[offset])?;
                    return Ok(ExtractedHashCells::default());
                }

                let mut preimage_indices_iter = preimage_indices.iter();
                let mut digest_indices_iter = digest_indices.iter();

                let mut cur_preimage_index = preimage_indices_iter.next();
                let mut cur_digest_index = digest_indices_iter.next();

                // ====================================================
                // Step 1. Extract the hash cells
                // ====================================================
                let mut hash_input_cells = vec![];
                let mut hash_output_cells = vec![];
                let mut data_rlc_cells = vec![];
                let mut hash_input_len_cells = vec![];
                let mut is_final_cells = vec![];

                let timer = start_timer!(|| "assign row");
                log::trace!("witness length: {}", witness.len());
                let input_bytes_col_idx =
                    keccak_packed_multi::get_input_bytes_col_idx_in_cell_manager()
                        + <KeccakTable as LookupTable<Fr>>::columns(&keccak_config.keccak_table)
                            .len()
                        - 1;
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row = keccak_config.set_row(&mut region, offset, keccak_row)?;

                    if cur_preimage_index.is_some() && *cur_preimage_index.unwrap() == offset {
                        hash_input_cells.push(row[input_bytes_col_idx].clone());
                        cur_preimage_index = preimage_indices_iter.next();
                    }
                    if cur_digest_index.is_some() && *cur_digest_index.unwrap() == offset {
                        // last column is Keccak output in Keccak circuit
                        hash_output_cells.push(row.last().unwrap().clone()); // sage unwrap
                        cur_digest_index = digest_indices_iter.next();
                    }
                    if offset % keccak_f_rows == 0 && offset / keccak_f_rows <= max_keccak_updates {
                        // first column is is_final
                        is_final_cells.push(row[0].clone());
                        // second column is data rlc
                        data_rlc_cells.push(row[1].clone());
                        // third column is hash len
                        hash_input_len_cells.push(row[2].clone());
                    }
                }
                end_timer!(timer);
                for (i, e) in is_final_cells.iter().enumerate() {
                    log::trace!("{}-th round is final {:?}", i, e.value());
                }

                // sanity
                assert_eq!(
                    hash_input_cells.len(),
                    max_keccak_updates * INPUT_LEN_PER_ROUND
                );
                assert_eq!(hash_output_cells.len(), (MAX_AGG_SNARKS + 6) * DIGEST_LEN);

                keccak_config
                    .keccak_table
                    .annotate_columns_in_region(&mut region);
                keccak_config.annotate_circuit(&mut region);
                Ok(ExtractedHashCells {
                    hash_input_cells,
                    hash_output_cells,
                    data_rlc_cells,
                    hash_input_len_cells,
                    is_final_cells,
                })
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("assign keccak rows: {e}")))?;

    for (i, e) in extracted_hash_cells.hash_input_len_cells.iter().enumerate() {
        log::trace!("{}'s round hash input len {:?}", i, e.value())
    }

    Ok(extracted_hash_cells)
}

// Assert the following constraints
// 2. batch_pi_hash used same roots as chunk_pi_hash
// 2.1. batch_pi_hash and chunk[0] use a same prev_state_root
// 2.2. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same post_state_root
// 2.3. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same withdraw_root
// 5. batch and all its chunks use a same chain id
fn copy_constraints(
    layouter: &mut impl Layouter<Fr>,
    hash_input_cells: &[AssignedCell<Fr, Fr>],
) -> Result<(), Error> {
    let mut is_first_time = true;

    layouter
        .assign_region(
            || "copy constraints",
            |mut region| -> Result<(), halo2_proofs::plonk::Error> {
                if is_first_time {
                    // this region only use copy constraints and do not affect the shape of the
                    // layouter
                    is_first_time = false;
                    return Ok(());
                }
                // ====================================================
                // parse the hashes
                // ====================================================
                // preimages
                let (
                    batch_pi_hash_preimage,
                    chunk_pi_hash_preimages,
                    challenge_point_hash_preimage,
                    _potential_batch_data_hash_preimage,
                ) = parse_hash_preimage_cells(hash_input_cells);

                // ====================================================
                // Constraint the relations between hash preimages
                // via copy constraints
                // ====================================================
                //
                // 2 batch_pi_hash used same roots as chunk_pi_hash
                //
                // batch_pi_hash =
                //   keccak(
                //      chain_id ||
                //      chunk[0].prev_state_root ||
                //      chunk[k-1].post_state_root ||
                //      chunk[k-1].withdraw_root ||
                //      batchData_hash )
                //
                // chunk[i].piHash =
                //   keccak(
                //        chain id ||
                //        chunk[i].prevStateRoot ||
                //        chunk[i].postStateRoot ||
                //        chunk[i].withdrawRoot  ||
                //        chunk[i].datahash)
                //
                // PREV_STATE_ROOT_INDEX, POST_STATE_ROOT_INDEX, WITHDRAW_ROOT_INDEX
                // used below are byte positions for
                // prev_state_root, post_state_root, withdraw_root
                for i in 0..DIGEST_LEN {
                    // 2.1 chunk[0].prev_state_root
                    // sanity check
                    assert_equal(
                        &batch_pi_hash_preimage[i + PREV_STATE_ROOT_INDEX],
                        &chunk_pi_hash_preimages[0][i + PREV_STATE_ROOT_INDEX],
                        format!(
                            "chunk and batch's prev_state_root do not match: {:?} {:?}",
                            &batch_pi_hash_preimage[i + PREV_STATE_ROOT_INDEX].value(),
                            &chunk_pi_hash_preimages[0][i + PREV_STATE_ROOT_INDEX].value(),
                        )
                        .as_str(),
                    )?;
                    region.constrain_equal(
                        batch_pi_hash_preimage[i + PREV_STATE_ROOT_INDEX].cell(),
                        chunk_pi_hash_preimages[0][i + PREV_STATE_ROOT_INDEX].cell(),
                    )?;
                    // 2.2 chunk[k-1].post_state_root
                    // sanity check
                    assert_equal(
                        &batch_pi_hash_preimage[i + POST_STATE_ROOT_INDEX],
                        &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + POST_STATE_ROOT_INDEX],
                        format!(
                            "chunk and batch's post_state_root do not match: {:?} {:?}",
                            &batch_pi_hash_preimage[i + POST_STATE_ROOT_INDEX].value(),
                            &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + POST_STATE_ROOT_INDEX]
                                .value(),
                        )
                        .as_str(),
                    )?;
                    region.constrain_equal(
                        batch_pi_hash_preimage[i + POST_STATE_ROOT_INDEX].cell(),
                        chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + POST_STATE_ROOT_INDEX]
                            .cell(),
                    )?;
                    // 2.3 chunk[k-1].withdraw_root
                    assert_equal(
                        &batch_pi_hash_preimage[i + WITHDRAW_ROOT_INDEX],
                        &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + WITHDRAW_ROOT_INDEX],
                        format!(
                            "chunk and batch's withdraw_root do not match: {:?} {:?}",
                            &batch_pi_hash_preimage[i + WITHDRAW_ROOT_INDEX].value(),
                            &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + WITHDRAW_ROOT_INDEX]
                                .value(),
                        )
                        .as_str(),
                    )?;
                    region.constrain_equal(
                        batch_pi_hash_preimage[i + WITHDRAW_ROOT_INDEX].cell(),
                        chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + WITHDRAW_ROOT_INDEX].cell(),
                    )?;
                }

                // 5 assert hashes use a same chain id
                for (i, chunk_pi_hash_preimage) in chunk_pi_hash_preimages.iter().enumerate() {
                    for (lhs, rhs) in batch_pi_hash_preimage
                        .iter()
                        .take(CHAIN_ID_LEN)
                        .zip(chunk_pi_hash_preimage.iter().take(CHAIN_ID_LEN))
                    {
                        // sanity check
                        assert_equal(
                            lhs,
                            rhs,
                            format!(
                                "chunk_{i} and batch's chain id do not match: {:?} {:?}",
                                &lhs.value(),
                                &rhs.value(),
                            )
                            .as_str(),
                        )?;
                        region.constrain_equal(lhs.cell(), rhs.cell())?;
                    }
                }
                // assert batch_data_hash preimage equal challenge point hash preimage
                for i in 0..48 {
                    assert_equal(
                        &batch_pi_hash_preimage[BATCH_COMMIT_INDEX + i],
                        &challenge_point_hash_preimage[i],
                        format!(
                            "batch commit and challenge_point commit id do not match: {:?} {:?}",
                            &batch_pi_hash_preimage[BATCH_COMMIT_INDEX + i].value(),
                            &challenge_point_hash_preimage[i].value(),
                        )
                        .as_str(),
                    )?;
                    region.constrain_equal(
                        batch_pi_hash_preimage[BATCH_COMMIT_INDEX + i].cell(),
                        challenge_point_hash_preimage[i].cell(),
                    )?;
                }
                // for i in 0..32{
                //     assert_equal(
                //         &batch_pi_hash_preimage[CHUNK_DATA_HASH_INDEX + i],
                //         &challenge_point_hash_preimage[48 + i],
                //         format!(
                //             "batch data hash and challenge_point data hash do not match: {:?}
                // {:?}",             &batch_pi_hash_preimage[CHUNK_DATA_HASH_INDEX
                // + i].value(),             &challenge_point_hash_preimage[48 +
                // i].value(),         )
                //         .as_str(),
                //     )?;
                //     region.constrain_equal(batch_pi_hash_preimage[CHUNK_DATA_HASH_INDEX +
                // i].cell(), challenge_point_hash_preimage[48 + i].cell()); }

                Ok(())
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("assign keccak rows: {e}")))?;
    Ok(())
}

// Assert the following constraints
// This function asserts the following constraints on the hashes
// 1. batch_data_hash digest is reused for public input hashx
// 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded
// 4. chunks are continuous: they are linked via the state roots
// 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when chunk[i] is
// padded
// 7. the hash input length are correct
// - first MAX_AGG_SNARKS + 1 hashes all have 136 + 192 bytes input
// - batch's data_hash length is 32 * number_of_valid_snarks
// 8. batch data hash is correct w.r.t. its RLCs
// 9. is_final_cells are set correctly
// 10. batch_pi_hash challenge point == chunk_pi_hash challenge point
//     batch_pi_hash result == sum(valid chunk_pi_hash partial result)
pub(crate) fn conditional_constraints(
    rlc_config: &RlcConfig,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    chunks_are_valid: &[bool],
    extracted_hash_cells: &ExtractedHashCells,
    assigned_result: &[AssignedValue<Fr>],
) -> Result<(), Error> {
    let mut first_pass = halo2_base::SKIP_FIRST_PASS;
    let ExtractedHashCells {
        hash_input_cells,
        hash_output_cells,
        hash_input_len_cells,
        data_rlc_cells,
        is_final_cells,
    } = extracted_hash_cells;

    layouter
        .assign_region(
            || "rlc conditional constraints",
            |mut region| -> Result<(), halo2_proofs::plonk::Error> {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                rlc_config.init(&mut region)?;
                let mut offset = 0;

                // ====================================================
                // build the flags to indicate the chunks are empty or not
                // ====================================================
                let chunk_is_valid_cells = chunks_are_valid
                    .iter()
                    .map(|chunk_is_valid| -> Result<_, halo2_proofs::plonk::Error> {
                        rlc_config.load_private(
                            &mut region,
                            &Fr::from(*chunk_is_valid as u64),
                            &mut offset,
                        )
                    })
                    .collect::<Result<Vec<_>, halo2_proofs::plonk::Error>>()?;
                let num_valid_snarks =
                    constrain_flags(rlc_config, &mut region, &chunk_is_valid_cells, &mut offset)?;

                log::trace!("number of valid chunks: {:?}", num_valid_snarks.value());
                //
                // if the num_of_valid_snarks <= 4, which only needs 1 keccak-f round. Therefore
                // the batch's data hash (input, len, data_rlc, output_rlc) are in the first 300
                // keccak rows;
                //
                // else if the num_of_valid_snarks <= 8, which needs
                // 2 keccak-f rounds. Therefore the batch's data hash (input, len, data_rlc,
                // output_rlc) are in the 2nd 300 keccak rows;
                //
                // else if the
                // num_of_valid_snarks <= 12, which needs 3 keccak-f rounds. Therefore the batch's
                // data hash (input, len, data_rlc, output_rlc) are in the 3rd 300 keccak rows;
                //
                // else if the
                // num_of_valid_snarks <= 16, which needs 4 keccak-f rounds. Therefore the batch's
                // data hash (input, len, data_rlc, output_rlc) are in the 4th 300 keccak rows;
                //
                // the following flag is build to indicate which row the final data_rlc exists
                //
                // #valid snarks | offset of data hash | flags
                // 1,2,3,4       | 0                   | 1, 0, 0, 0
                // 5,6,7,8       | 32                  | 0, 1, 0, 0
                // 9,10,11,12    | 64                  | 0, 0, 1, 0
                // 13,14,15,16   | 96                  | 0, 0, 0, 1

                let five = {
                    let five = rlc_config.load_private(&mut region, &Fr::from(5), &mut offset)?;
                    let five_cell = rlc_config.five_cell(five.cell().region_index);
                    region.constrain_equal(five_cell, five.cell())?;
                    five
                };
                let nine = {
                    let nine = rlc_config.load_private(&mut region, &Fr::from(9), &mut offset)?;
                    let nine_cell = rlc_config.nine_cell(nine.cell().region_index);
                    region.constrain_equal(nine_cell, nine.cell())?;
                    nine
                };
                let thirteen = {
                    let thirteen =
                        rlc_config.load_private(&mut region, &Fr::from(13), &mut offset)?;
                    let thirteen_cell = rlc_config.thirteen_cell(thirteen.cell().region_index);
                    region.constrain_equal(thirteen_cell, thirteen.cell())?;
                    thirteen
                };

                let smaller_or_eq_4 = rlc_config.is_smaller_than(
                    &mut region,
                    &num_valid_snarks,
                    &five,
                    &mut offset,
                )?;
                let greater_than_4 = rlc_config.not(&mut region, &smaller_or_eq_4, &mut offset)?;
                let smaller_or_eq_8 = rlc_config.is_smaller_than(
                    &mut region,
                    &num_valid_snarks,
                    &nine,
                    &mut offset,
                )?;
                let greater_than_8 = rlc_config.not(&mut region, &smaller_or_eq_8, &mut offset)?;
                let smaller_or_eq_12 = rlc_config.is_smaller_than(
                    &mut region,
                    &num_valid_snarks,
                    &thirteen,
                    &mut offset,
                )?;
                let greater_than_12 =
                    rlc_config.not(&mut region, &smaller_or_eq_12, &mut offset)?;

                let flag1 = smaller_or_eq_4;
                let flag2 =
                    rlc_config.mul(&mut region, &greater_than_4, &smaller_or_eq_8, &mut offset)?;
                let flag3 =
                    rlc_config.mul(&mut region, &greater_than_8, &smaller_or_eq_12, &mut offset)?;
                let flag4 = greater_than_12;

                log::trace!(
                    "flags: {:?} {:?} {:?} {:?}",
                    flag1.value(),
                    flag2.value(),
                    flag3.value(),
                    flag4.value()
                );
                // ====================================================
                // parse the hashes
                // ====================================================
                // preimages
                let (
                    batch_pi_hash_preimage,
                    chunk_pi_hash_preimages,
                    challenge_point_hash_preimage,
                    potential_batch_data_hash_preimage,
                ) = parse_hash_preimage_cells(hash_input_cells);

                // digests
                let (
                    _batch_pi_hash_digest,
                    _chunk_pi_hash_digests,
                    challenge_point_hash_digest,
                    potential_batch_data_hash_digest,
                ) = parse_hash_digest_cells(hash_output_cells);

                // 10. batch_pi_hash challenge point == chunk_pi_hash challenge point
                //     batch_pi_hash result == sum(valid chunk_pi_hash partial result)
                for j in 0..MAX_AGG_SNARKS{
                    for i in 0..(3*DIGEST_LEN){
                        assert_equal(
                            &batch_pi_hash_preimage[i + BATCH_CHALLENGE_POINT_INDEX],
                            &chunk_pi_hash_preimages[j][i + CHALLENGE_POINT_INDEX],
                            format!(
                                "chunk and batch's challenge_point do not match: {:?} {:?}",
                                &batch_pi_hash_preimage[i + BATCH_CHALLENGE_POINT_INDEX].value(),
                                &chunk_pi_hash_preimages[j][i + CHALLENGE_POINT_INDEX].value(),
                            )
                            .as_str(),
                        )?;
                        region.constrain_equal(
                            batch_pi_hash_preimage[i + BATCH_CHALLENGE_POINT_INDEX].cell(),
                            chunk_pi_hash_preimages[j][i + CHALLENGE_POINT_INDEX].cell(),
                        )?;
                    }
                }
                let partial_result_len = (assigned_result.len() / 3) - 1;

                let two_hundred_and_fifty_six = {
                    let two_hundred_and_fifty_six = rlc_config.load_private(&mut region, &Fr::from(256), &mut offset)?;
                    let two_hundred_and_fifty_six_cell = rlc_config.two_hundred_and_fifty_six_cell(two_hundred_and_fifty_six.cell().region_index);
                    region.constrain_equal(two_hundred_and_fifty_six_cell, two_hundred_and_fifty_six.cell())?;
                    two_hundred_and_fifty_six
                };
                let mut result_preimage_rlc = vec![];
                for i in 0..partial_result_len{
                    result_preimage_rlc.push(rlc_config.rlc(&mut region, &chunk_pi_hash_preimages[i][RESULT_INDEX..RESULT_INDEX+32], &two_hundred_and_fifty_six, &mut offset)?);
                    result_preimage_rlc.push(rlc_config.rlc(&mut region, &chunk_pi_hash_preimages[i][RESULT_INDEX+32..RESULT_INDEX+64], &two_hundred_and_fifty_six, &mut offset)?);
                    result_preimage_rlc.push(rlc_config.rlc(&mut region, &chunk_pi_hash_preimages[i][RESULT_INDEX+64..RESULT_INDEX+96], &two_hundred_and_fifty_six, &mut offset)?);
                }
                result_preimage_rlc.push(rlc_config.rlc(&mut region, &batch_pi_hash_preimage[BATCH_RESULT_INDEX..BATCH_RESULT_INDEX+32], &two_hundred_and_fifty_six, &mut offset)?);
                result_preimage_rlc.push(rlc_config.rlc(&mut region, &batch_pi_hash_preimage[BATCH_RESULT_INDEX+32..BATCH_RESULT_INDEX+64], &two_hundred_and_fifty_six, &mut offset)?);
                result_preimage_rlc.push(rlc_config.rlc(&mut region, &batch_pi_hash_preimage[BATCH_RESULT_INDEX+64..BATCH_RESULT_INDEX+96], &two_hundred_and_fifty_six, &mut offset)?);

                for i in 0..assigned_result.len(){
                    let lhs = &assigned_result[i];
                    let rhs = &result_preimage_rlc[i];

                    log::trace!("{i}th assigned result:{:?}; result_preimage_rlc{:?}", lhs.clone().value(), rhs.clone().value());
                    // sanity check
                    assert_equal_value(
                        lhs.value(),
                        rhs.value(),
                        format!(
                            " assigned result and result_preimage_rlc do not match: {:?} {:?}",
                            &lhs.value(),
                            &rhs.value(),
                        )
                        .as_str(),
                    )?;
                    region.constrain_equal(lhs.cell(), rhs.cell())?;
                }

                //11.challenge point digest top_byte equals 0 and other bytes equal batch_pi_hash_preimage challenge_point
                let zero = {
                    let zero = rlc_config.load_private(&mut region, &Fr::from(0), &mut offset)?;
                    let zero_cell = rlc_config.zero_cell(zero.cell().region_index);
                    region.constrain_equal(zero_cell, zero.cell())?;
                    zero
                };

                for i in (0..21).chain(32..52).chain(64..86){
                    assert_equal(
                        &batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + i],
                        &zero,
                        format!(
                            " i:{:?} batch_pi_hash_preimage and zero do not match: {:?} {:?}",
                            i,
                            &batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + i].value(),
                            &zero.value(),
                        )
                        .as_str(),
                    )?;
                }
                for i in 0..4 {
                    for j in 0..8{
                        if(i == 3) & (j == 7) {

                        } else if (i * 8 + j) < 11 {
                            // 31 .. 21
                            assert_equal(
                                &batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + 31 - (i * 8 + j)],
                                &challenge_point_hash_digest[(3 - i) * 8 + j],
                                format!(
                                    " i:{:?} j:{:?} batch_pi_hash_preimage and challenge point digest do not match in limb1: {:?} {:?}",
                                    i,
                                    j,
                                    &batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + 31 - (i * 8 + j)].value(),
                                    &challenge_point_hash_digest[(3 - i) * 8 + j].value(),
                                )
                                .as_str(),
                            )?;
                            region.constrain_equal(batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + 31 - (i * 8 + j)].cell(), challenge_point_hash_digest[(3 - i) * 8 + j].cell())?;
                        } else if 10 < (i * 8 + j) && (i * 8 + j) < 22 {
                            // 63 .. 53
                            assert_equal(
                                &batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + 63 - (i * 8 + j - 11)],
                                &challenge_point_hash_digest[(3 - i) * 8 + j],
                                format!(
                                    " batch_pi_hash_preimage and challenge point digest do not match in limb2: {:?} {:?}",
                                    &batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + 63 - (i * 8 + j - 11)].value(),
                                    &challenge_point_hash_digest[(3 - i) * 8 + j].value(),
                                )
                                .as_str(),
                            )?;
                            region.constrain_equal(batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + 63 - (i * 8 + j - 11)].cell(), challenge_point_hash_digest[(3 - i) * 8 + j].cell())?;
                        } else if 21 < (i * 8 + j) && (i * 8 + j) < 31{
                            //95 .. 87
                            assert_equal(
                                &batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + 95 - (i * 8 + j - 22)],
                                &challenge_point_hash_digest[(3 - i) * 8 + j],
                                format!(
                                    " batch_pi_hash_preimage and challenge point digest do not match in limb3: {:?} {:?}",
                                    &batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + 95 - (i * 8 + j - 22)].value(),
                                    &challenge_point_hash_digest[(3 - i) * 8 + j].value(),
                                )
                                .as_str(),
                            )?;
                            region.constrain_equal(batch_pi_hash_preimage[BATCH_CHALLENGE_POINT_INDEX + 95 - (i * 8 + j - 22)].cell(), challenge_point_hash_digest[(3 - i) * 8 + j].cell())?;
                        }
                }
            }

                // ====================================================
                // start the actual statements
                // ====================================================
                //
                // 1 batch_data_hash digest is reused for public input hash and challenge point hash
                //
                // the following part of the code is hard coded for the case where
                //   MAX_AGG_SNARKS <= 10
                // in theory it may support up to 12 SNARKS (not tested)
                // more SNARKs beyond 12 will require a revamp of the circuit
                //
                // public input hash is build as
                //  keccak(
                //      chain_id ||
                //      chunk[0].prev_state_root ||
                //      chunk[k-1].post_state_root ||
                //      chunk[k-1].withdraw_root ||
                //      batch_data_hash )
                //
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
                //
                //
                // #valid snarks | offset of data hash | flags
                // 1,2,3,4       | 0                   | 1, 0, 0, 0
                // 5,6,7,8       | 32                  | 0, 1, 0, 0
                // 9,10,11,12    | 64                  | 0, 0, 1, 0
                // 13,14,15,16   | 96                  | 0, 0, 0, 1
                for i in 0..4 {
                    for j in 0..8 {
                        // sanity check
                        assert_exist(
                            &batch_pi_hash_preimage[i * 8 + j + CHUNK_DATA_HASH_INDEX],
                            &[
                                potential_batch_data_hash_digest[(3 - i) * 8 + j].clone(),
                                potential_batch_data_hash_digest[(3 - i) * 8 + j + 32].clone(),
                                potential_batch_data_hash_digest[(3 - i) * 8 + j + 64].clone(),
                                potential_batch_data_hash_digest[(3 - i) * 8 + j + 96].clone(),
                            ],
                        )?;
                        assert_exist(
                            &challenge_point_hash_preimage[i * 8 + j + 48],
                            &[
                                potential_batch_data_hash_digest[(3 - i) * 8 + j].clone(),
                                potential_batch_data_hash_digest[(3 - i) * 8 + j + 32].clone(),
                                potential_batch_data_hash_digest[(3 - i) * 8 + j + 64].clone(),
                                potential_batch_data_hash_digest[(3 - i) * 8 + j + 96].clone(),
                            ],
                        )?;
                        // assert
                        // batch_pi_hash_preimage[i * 8 + j + CHUNK_DATA_HASH_INDEX]
                        // = flag1 * potential_batch_data_hash_digest[(3 - i) * 8 + j]
                        // + flag2 * potential_batch_data_hash_digest[(3 - i) * 8 + j + 32]
                        // + flag3 * potential_batch_data_hash_digest[(3 - i) * 8 + j + 64]
                        // + flag4 * potential_batch_data_hash_digest[(3 - i) * 8 + j + 96]

                        let rhs = rlc_config.mul(
                            &mut region,
                            &flag1,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j],
                            &mut offset,
                        )?;
                        let rhs = rlc_config.mul_add(
                            &mut region,
                            &flag2,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + 32],
                            &rhs,
                            &mut offset,
                        )?;
                        let rhs = rlc_config.mul_add(
                            &mut region,
                            &flag3,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + 64],
                            &rhs,
                            &mut offset,
                        )?;
                        let rhs = rlc_config.mul_add(
                            &mut region,
                            &flag4,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + 96],
                            &rhs,
                            &mut offset,
                        )?;

                        region.constrain_equal(
                            batch_pi_hash_preimage[i * 8 + j + CHUNK_DATA_HASH_INDEX].cell(),
                            rhs.cell(),
                        )?;
                        region.constrain_equal(
                            challenge_point_hash_preimage[i * 8 + j + 48].cell(),
                            rhs.cell(),
                        )?;
                    }
                }

                // 3 batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when
                // chunk[i] is not padded
                //
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
                //
                // chunk[i].piHash =
                //     keccak(
                //        &chain id ||
                //        chunk[i].prevStateRoot ||
                //        chunk[i].postStateRoot ||
                //        chunk[i].withdrawRoot  ||
                //        chunk[i].datahash)
                for i in 0..MAX_AGG_SNARKS {
                    for j in 0..DIGEST_LEN {
                        assert_conditional_equal(
                            &chunk_pi_hash_preimages[i][j + CHUNK_DATA_HASH_INDEX],
                            &potential_batch_data_hash_preimage[i * DIGEST_LEN + j],
                            &chunk_is_valid_cells[i],
                            format!(
                                "chunk_{i}'s data hash does not match batch's: {:?} {:?} {:?}",
                                &chunk_pi_hash_preimages[i][j + CHUNK_DATA_HASH_INDEX].value(),
                                &potential_batch_data_hash_preimage[i * DIGEST_LEN + j].value(),
                                &chunk_is_valid_cells[i].value()
                            )
                            .as_str(),
                        )?;
                        rlc_config.conditional_enforce_equal(
                            &mut region,
                            &chunk_pi_hash_preimages[i][j + CHUNK_DATA_HASH_INDEX],
                            &potential_batch_data_hash_preimage[i * DIGEST_LEN + j],
                            &chunk_is_valid_cells[i],
                            &mut offset,
                        )?;
                    }
                }

                // 4  __valid__ chunks are continuous: they are linked via the state roots
                for i in 0..MAX_AGG_SNARKS - 1 {
                    for j in 0..DIGEST_LEN {
                        // sanity check
                        assert_conditional_equal(
                            &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j],
                            &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j],
                            &chunk_is_valid_cells[i + 1],
                            format!(
                                "chunk_{i} is not continuous: {:?} {:?} {:?}",
                                &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j].value(),
                                &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j].value(),
                                &chunk_is_valid_cells[i + 1].value(),
                            )
                            .as_str(),
                        )?;
                        rlc_config.conditional_enforce_equal(
                            &mut region,
                            &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j],
                            &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j],
                            &chunk_is_valid_cells[i + 1],
                            &mut offset,
                        )?;
                    }
                }

                // 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when
                // chunk[i] is padded
                let chunks_are_padding = chunk_is_valid_cells
                    .iter()
                    .map(|chunk_is_valid| rlc_config.not(&mut region, chunk_is_valid, &mut offset))
                    .collect::<Result<Vec<_>, halo2_proofs::plonk::Error>>()?;

                let chunk_pi_hash_rlc_cells = parse_pi_hash_rlc_cells(data_rlc_cells);

                for i in 1..MAX_AGG_SNARKS {
                    rlc_config.conditional_enforce_equal(
                        &mut region,
                        chunk_pi_hash_rlc_cells[i - 1],
                        chunk_pi_hash_rlc_cells[i],
                        &chunks_are_padding[i],
                        &mut offset,
                    )?;
                }

                for (i, (e, f)) in chunk_pi_hash_rlc_cells
                    .iter()
                    .zip(chunk_is_valid_cells.iter())
                    .enumerate()
                {
                    log::trace!("{i}-th chunk rlc:      {:?}", e.value());
                    log::trace!("{i}-th chunk is valid: {:?}", f.value());
                }

                // 7. the hash input length are correct
                // - first batch pi hash have 376 bytes
                // - MAX_AGG_SNARKS hashes all have 328 bytes input
                // - batch's data_hash length is 32 * number_of_valid_snarks

                //first hash
                hash_input_len_cells
                    .iter()
                    .skip(1)
                    .take(3)
                    .chunks(3)
                    .into_iter()
                    .try_for_each(|chunk| {
                        let cur_hash_len = chunk.last().unwrap(); // safe unwrap
                        region.constrain_equal(
                            cur_hash_len.cell(),
                            rlc_config
                                .three_hundred_and_seventy_six_cell(cur_hash_len.cell().region_index),
                        )
                    })?;

                // MAX_AGG_SNARKS hashes
                hash_input_len_cells
                    .iter()
                    .skip(4)
                    .take((MAX_AGG_SNARKS) * 3)
                    .chunks(3)
                    .into_iter()
                    .try_for_each(|chunk| {
                        let cur_hash_len = chunk.last().unwrap(); // safe unwrap
                        region.constrain_equal(
                            cur_hash_len.cell(),
                            rlc_config
                                .three_hundred_and_twenty_eight_cell(cur_hash_len.cell().region_index),
                        )
                    })?;

                // - batch's data_hash length is 32 * number_of_valid_snarks
                let const32 = rlc_config.load_private(&mut region, &Fr::from(32), &mut offset)?;
                let const32_cell = rlc_config.thirty_two_cell(const32.cell().region_index);
                region.constrain_equal(const32.cell(), const32_cell)?;
                let data_hash_inputs_len =
                    rlc_config.mul(&mut region, &num_valid_snarks, &const32, &mut offset)?;

                // sanity check
                assert_exist(
                    &data_hash_inputs_len,
                    &[
                        hash_input_len_cells[MAX_AGG_SNARKS * 3 + 5].clone(),
                        hash_input_len_cells[MAX_AGG_SNARKS * 3 + 6].clone(),
                        hash_input_len_cells[MAX_AGG_SNARKS * 3 + 7].clone(),
                        hash_input_len_cells[MAX_AGG_SNARKS * 3 + 8].clone(),
                    ],
                )?;

                log::trace!("data_hash_inputs: {:?}", data_hash_inputs_len.value());
                log::trace!(
                    "candidate 1: {:?}",
                    hash_input_len_cells[MAX_AGG_SNARKS * 3 + 5].value()
                );
                log::trace!(
                    "candidate 2: {:?}",
                    hash_input_len_cells[MAX_AGG_SNARKS * 3 + 6].value()
                );
                log::trace!(
                    "candidate 3: {:?}",
                    hash_input_len_cells[MAX_AGG_SNARKS * 3 + 7].value()
                );
                log::trace!(
                    "candidate 4: {:?}",
                    hash_input_len_cells[MAX_AGG_SNARKS * 3 + 8].value()
                );

                let mut data_hash_inputs_len_rec = rlc_config.mul(
                    &mut region,
                    &hash_input_len_cells[MAX_AGG_SNARKS * 3 + 5],
                    &flag1,
                    &mut offset,
                )?;
                data_hash_inputs_len_rec = rlc_config.mul_add(
                    &mut region,
                    &hash_input_len_cells[MAX_AGG_SNARKS * 3 + 6],
                    &flag2,
                    &data_hash_inputs_len_rec,
                    &mut offset,
                )?;
                data_hash_inputs_len_rec = rlc_config.mul_add(
                    &mut region,
                    &hash_input_len_cells[MAX_AGG_SNARKS * 3 + 7],
                    &flag3,
                    &data_hash_inputs_len_rec,
                    &mut offset,
                )?;
                data_hash_inputs_len_rec = rlc_config.mul_add(
                    &mut region,
                    &hash_input_len_cells[MAX_AGG_SNARKS * 3 + 8],
                    &flag4,
                    &data_hash_inputs_len_rec,
                    &mut offset,
                )?;

                // sanity check
                assert_equal(
                    &data_hash_inputs_len,
                    &data_hash_inputs_len_rec,
                    format!(
                        "data_hash_input_len do not match: {:?} {:?}",
                        &data_hash_inputs_len.value(),
                        &data_hash_inputs_len_rec.value(),
                    )
                    .as_str(),
                )?;
                region.constrain_equal(
                    data_hash_inputs_len.cell(),
                    data_hash_inputs_len_rec.cell(),
                )?;

                // 8. batch data hash is correct w.r.t. its RLCs
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
                let challenge_cell =
                    rlc_config.read_challenge(&mut region, challenges, &mut offset)?;

                let flags = chunk_is_valid_cells
                    .iter()
                    .flat_map(|cell| vec![cell; 32])
                    .cloned()
                    .collect::<Vec<_>>();

                let rlc_cell = rlc_config.rlc_with_flag(
                    &mut region,
                    potential_batch_data_hash_preimage[..DIGEST_LEN * MAX_AGG_SNARKS].as_ref(),
                    &challenge_cell,
                    &flags,
                    &mut offset,
                )?;

                assert_exist(
                    &rlc_cell,
                    &[
                        data_rlc_cells[MAX_AGG_SNARKS * 3 + 5].clone(),
                        data_rlc_cells[MAX_AGG_SNARKS * 3 + 6].clone(),
                        data_rlc_cells[MAX_AGG_SNARKS * 3 + 7].clone(),
                        data_rlc_cells[MAX_AGG_SNARKS * 3 + 8].clone(),
                    ],
                )?;
                log::trace!("rlc from chip {:?}", rlc_cell.value());
                log::trace!(
                    "rlc from table {:?}",
                    data_rlc_cells[MAX_AGG_SNARKS * 3 + 5].value()
                );
                log::trace!(
                    "rlc from table {:?}",
                    data_rlc_cells[MAX_AGG_SNARKS * 3 + 6].value()
                );
                log::trace!(
                    "rlc from table {:?}",
                    data_rlc_cells[MAX_AGG_SNARKS * 3 + 7].value()
                );

                // assertion
                let t1 = rlc_config.sub(
                    &mut region,
                    &rlc_cell,
                    &data_rlc_cells[MAX_AGG_SNARKS * 3 + 5],
                    &mut offset,
                )?;
                let t2 = rlc_config.sub(
                    &mut region,
                    &rlc_cell,
                    &data_rlc_cells[MAX_AGG_SNARKS * 3 + 6],
                    &mut offset,
                )?;
                let t3 = rlc_config.sub(
                    &mut region,
                    &rlc_cell,
                    &data_rlc_cells[MAX_AGG_SNARKS * 3 + 7],
                    &mut offset,
                )?;
                let t4 = rlc_config.sub(
                    &mut region,
                    &rlc_cell,
                    &data_rlc_cells[MAX_AGG_SNARKS * 3 + 8],
                    &mut offset,
                )?;
                let t1t2 = rlc_config.mul(&mut region, &t1, &t2, &mut offset)?;
                let t1t2t3 = rlc_config.mul(&mut region, &t1t2, &t3, &mut offset)?;
                let t1t2t3t4 = rlc_config.mul(&mut region, &t1t2t3, &t4, &mut offset)?;
                rlc_config.enforce_zero(&mut region, &t1t2t3t4)?;

                // 9. is_final_cells are set correctly
                // the is_final_cells are set as
                // index                     | value | comments
                // --------------------------|-------|------------
                // 0                         | 0     | 0-th row is prefix pad
                // 1                         | 0     | first keccak:
                // 2                         | 1     |   batch_pi_hash use 2 rounds
                // 3                         | 0     | second keccak:
                // 4                         | 1     |   chunk[0].pi_hash use 2 rounds
                // 5                         | 0     | third keccak:
                // 6                         | 1     |   chunk[1].pi_hash use 2 rounds
                // ...
                // 2*(MAX_AGG_SNARKS) + 1    | 0     | MAX_AGG_SNARKS+1's keccak
                // 2*(MAX_AGG_SNARKS) + 2    | 1     |   chunk[MAX_AGG_SNARKS].pi_hash use 2 rounds
                // 2*(MAX_AGG_SNARKS) + 3    | a     | MAX_AGG_SNARKS+2's keccak
                // 2*(MAX_AGG_SNARKS) + 4    | b     |   batch_data_hash may use 1, 2, 3
                // 2*(MAX_AGG_SNARKS) + 5    | c     |   or 4 rounds
                // 2*(MAX_AGG_SNARKS) + 6    | d     |
                //
                // so a,b,c are constrained as follows
                //
                // #valid snarks | flags        | a | b | c | d
                // 1,2,3,4       | 1, 0, 0, 0   | 1 | - | - | -
                // 5,6,7,8       | 0, 1, 0, 0   | 0 | 1 | - | -
                // 9,10,11,12    | 0, 0, 1, 0   | 0 | 0 | 1 | -
                // 13,14,15,16   | 0, 0, 0, 1   | 0 | 0 | 0 | 1

                // first MAX_AGG_SNARKS + 1 keccak
                for mut chunk in is_final_cells
                    .iter()
                    .skip(1)
                    .take((MAX_AGG_SNARKS + 1) * 3)
                    .into_iter()
                    .chunks(3)
                    .into_iter()
                {
                    // first round
                    let first_round_cell = chunk.next().unwrap();
                    let second_round_cell = chunk.next().unwrap();
                    let third_round_cell = chunk.next().unwrap();
                    region.constrain_equal(
                        first_round_cell.cell(),
                        rlc_config.zero_cell(first_round_cell.cell().region_index),
                    )?;
                    region.constrain_equal(
                        second_round_cell.cell(),
                        rlc_config.zero_cell(second_round_cell.cell().region_index),
                    )?;
                    region.constrain_equal(
                        third_round_cell.cell(),
                        rlc_config.one_cell(third_round_cell.cell().region_index),
                    )?;
                }
                // last keccak
                // we constrain a * flag1 + b * flag2 + c * flag3 + d * flag4 == 1
                let a = &is_final_cells[3 * (MAX_AGG_SNARKS) + 5];
                let b = &is_final_cells[3 * (MAX_AGG_SNARKS) + 6];
                let c = &is_final_cells[3 * (MAX_AGG_SNARKS) + 7];
                let d = &is_final_cells[3 * (MAX_AGG_SNARKS) + 8];
                let mut left = rlc_config.mul(&mut region, a, &flag1, &mut offset)?;
                left = rlc_config.mul_add(&mut region, b, &flag2, &left, &mut offset)?;
                left = rlc_config.mul_add(&mut region, c, &flag3, &left, &mut offset)?;
                left = rlc_config.mul_add(&mut region, d, &flag4, &left, &mut offset)?;

                log::trace!("left value: {:?}", left.value());
                region
                    .constrain_equal(left.cell(), rlc_config.one_cell(left.cell().region_index))?;

                log::trace!("rlc chip uses {} rows", offset);
                Ok(())
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("aggregation: {e}")))?;
    Ok(())
}

/// Input a list of flags whether the snark is valid
///
/// Assert the following relations on the flags:
/// - all elements are binary
/// - the first element is 1
/// - for the next elements, if the element is 1, the previous element must also be 1
///
/// Return a cell for number of valid snarks
fn constrain_flags(
    rlc_config: &RlcConfig,
    region: &mut Region<Fr>,
    chunk_are_valid: &[AssignedCell<Fr, Fr>],
    offset: &mut usize,
) -> Result<AssignedCell<Fr, Fr>, halo2_proofs::plonk::Error> {
    assert!(!chunk_are_valid.is_empty());

    let one = {
        let one = rlc_config.load_private(region, &Fr::one(), offset)?;
        let one_cell = rlc_config.one_cell(chunk_are_valid[0].cell().region_index);
        region.constrain_equal(one.cell(), one_cell)?;
        one
    };

    // the first element is 1
    region.constrain_equal(chunk_are_valid[0].cell(), one.cell())?;

    let mut res = chunk_are_valid[0].clone();
    for (index, cell) in chunk_are_valid.iter().enumerate().skip(1) {
        rlc_config.enforce_binary(region, cell, offset)?;

        // if the element is 1, the previous element must also be 1
        rlc_config.conditional_enforce_equal(
            region,
            &chunk_are_valid[index - 1],
            &one,
            cell,
            offset,
        )?;

        res = rlc_config.add(region, &res, cell, offset)?;
    }
    Ok(res)
}
