//! This module implements related functions that aggregates public inputs of many chunks into a
//! single one.

use std::vec;

use bls12_381::Scalar as Fp;
use eth_types::{Field, ToLittleEndian, H256, U256};
use ethers_core::utils::keccak256;
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::{decompose_biguint, fe_to_biguint};

use crate::constants::MAX_AGG_SNARKS;

use super::chunk::ChunkHash;

#[derive(Default, Debug, Clone)]
/// A batch is a set of MAX_AGG_SNARKS num of continuous chunks
/// - the first k chunks are from real traces
/// - the last (#MAX_AGG_SNARKS-k) chunks are from empty traces
/// A BatchHash consists of 2 hashes.
/// - batch_pi_hash   := keccak(chain_id || chunk_0.prev_state_root || chunk_k-1.post_state_root ||
///   chunk_k-1.withdraw_root || batch_data_hash)
/// - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
pub struct BatchHash {
    pub(crate) chain_id: u64,
    // chunks with padding.
    // - the first [0..number_of_valid_chunks) are real ones
    // - the last [number_of_valid_chunks, MAX_AGG_SNARKS) are padding
    pub(crate) chunks_with_padding: [ChunkHash; MAX_AGG_SNARKS],
    pub(crate) data_hash: H256,
    pub(crate) public_input_hash: H256,
    pub(crate) number_of_valid_chunks: usize,
    pub(crate) challenge_point:U256,
    pub(crate) result:U256,

}

impl BatchHash {
    /// Build Batch hash from an ordered list of #MAX_AGG_SNARKS of chunks.
    #[allow(dead_code)]
    pub fn construct(chunks_with_padding: &[ChunkHash]) -> Self {
        assert_eq!(
            chunks_with_padding.len(),
            MAX_AGG_SNARKS,
            "input chunk slice does not match MAX_AGG_SNARKS"
        );

        let number_of_valid_chunks = match chunks_with_padding
            .iter()
            .enumerate()
            .find(|(_index, chunk)| chunk.is_padding)
        {
            Some((index, _)) => index,
            None => MAX_AGG_SNARKS,
        };

        assert_ne!(
            number_of_valid_chunks, 0,
            "input chunk slice does not contain real chunks"
        );
        log::trace!("build a Batch with {number_of_valid_chunks} real chunks");

        log::trace!("chunks with padding");
        for (i, chunk) in chunks_with_padding.iter().enumerate() {
            log::trace!("{}-th chunk: {:?}", i, chunk);
        }

        // ========================
        // sanity checks
        // ========================
        // todo: return errors instead
        for i in 0..MAX_AGG_SNARKS - 1 {
            assert_eq!(
                chunks_with_padding[i].chain_id,
                chunks_with_padding[i + 1].chain_id,
            );
            if chunks_with_padding[i + 1].is_padding {
                assert_eq!(
                    chunks_with_padding[i + 1].data_hash,
                    chunks_with_padding[i].data_hash
                );
                assert_eq!(
                    chunks_with_padding[i + 1].prev_state_root,
                    chunks_with_padding[i].prev_state_root
                );
                assert_eq!(
                    chunks_with_padding[i + 1].post_state_root,
                    chunks_with_padding[i].post_state_root
                );
                assert_eq!(
                    chunks_with_padding[i + 1].withdraw_root,
                    chunks_with_padding[i].withdraw_root
                );
            } else {
                assert_eq!(
                    chunks_with_padding[i].post_state_root,
                    chunks_with_padding[i + 1].prev_state_root,
                );
                assert_eq!(
                    chunks_with_padding[i].challenge_point,
                    chunks_with_padding[i + 1].challenge_point,
                )
            }
        }

        // batch's data hash is build as
        //  keccak( chunk[0].data_hash || ... || chunk[k-1].data_hash)
        let preimage = chunks_with_padding
            .iter()
            .take(number_of_valid_chunks)
            .flat_map(|chunk_hash| chunk_hash.data_hash.0.iter())
            .cloned()
            .collect::<Vec<_>>();
        let data_hash = keccak256(preimage);

        // public input hash is build as
        //  keccak(
        //      chain_id ||
        //      chunk[0].prev_state_root ||
        //      chunk[k-1].post_state_root ||
        //      chunk[k-1].withdraw_root ||
        //      batch_data_hash || 
        //      challenge_point || 
        //      result)

        
        // add challenge_point and result to batch_hash
        let challenge_point = chunks_with_padding[0].challenge_point;
        let mut result   = Fp::from_bytes(&chunks_with_padding[0].partial_result.to_le_bytes()).unwrap();
        for i in 1..number_of_valid_chunks {
            result = result+Fp::from_bytes(&chunks_with_padding[i].partial_result.to_le_bytes()).unwrap();
        }

        let (cp_preimage, re_preimage) = Self::decompose_cp_result(challenge_point, U256::from_little_endian(&result.to_bytes()));

        let preimage = [
            chunks_with_padding[0].chain_id.to_be_bytes().as_ref(),
            chunks_with_padding[0].prev_state_root.as_bytes(),
            chunks_with_padding[MAX_AGG_SNARKS - 1]
                .post_state_root
                .as_bytes(),
            chunks_with_padding[MAX_AGG_SNARKS - 1]
                .withdraw_root
                .as_bytes(),
            data_hash.as_slice(),
            cp_preimage[0].as_slice(),
            cp_preimage[1].as_slice(),
            cp_preimage[2].as_slice(),
            re_preimage[0].as_slice(),
            re_preimage[1].as_slice(),
            re_preimage[2].as_slice(),
        ]
        .concat();

        let public_input_hash = keccak256(preimage);

        Self {
            chain_id: chunks_with_padding[0].chain_id,
            chunks_with_padding: chunks_with_padding.try_into().unwrap(), // safe unwrap
            data_hash: data_hash.into(),
            public_input_hash: public_input_hash.into(),
            number_of_valid_chunks,
            challenge_point,
            result: U256::from_little_endian(&result.to_bytes()),
        }
    }

    /// Extract all the hash inputs that will ever be used.
    /// There are MAX_AGG_SNARKS + 2 hashes.
    ///
    /// orders:
    /// - batch_public_input_hash
    /// - chunk\[i\].piHash for i in \[0, MAX_AGG_SNARKS)
    /// - batch_data_hash_preimage
    pub(crate) fn extract_hash_preimages(&self) -> Vec<Vec<u8>> {
        let mut res = vec![];

        // batchPiHash =
        //  keccak(
        //      chain_id ||
        //      chunk[0].prev_state_root ||
        //      chunk[k-1].post_state_root ||
        //      chunk[k-1].withdraw_root ||
        //      batch_data_hash || 
        //      challenge_point || 
        //      result)

        let (challenge_point_preimage, result_preimage) = Self::decompose_cp_result(self.challenge_point, self.result);


        let batch_public_input_hash_preimage = [
            self.chain_id.to_be_bytes().as_ref(),
            self.chunks_with_padding[0].prev_state_root.as_bytes(),
            self.chunks_with_padding[MAX_AGG_SNARKS - 1]
                .post_state_root
                .as_bytes(),
            self.chunks_with_padding[MAX_AGG_SNARKS - 1]
                .withdraw_root
                .as_bytes(),
            self.data_hash.as_bytes(),
            challenge_point_preimage[0].as_slice(),
            challenge_point_preimage[1].as_slice(),
            challenge_point_preimage[2].as_slice(),
            result_preimage[0].as_slice(),
            result_preimage[1].as_slice(),
            result_preimage[2].as_slice(),
        ]
        .concat();
        res.push(batch_public_input_hash_preimage);

        // compute piHash for each chunk for i in [0..MAX_AGG_SNARKS)
        // chunk[i].piHash =
        // keccak(
        //        chain id ||
        //        chunk[i].prevStateRoot || chunk[i].postStateRoot || chunk[i].withdrawRoot ||
        //        chunk[i].datahash || x || y)
        for chunk in self.chunks_with_padding.iter() {
            let (challenge_point_preimage, partial_result_preimage) = Self::decompose_cp_result(chunk.challenge_point, chunk.partial_result);
            let chunk_public_input_hash_preimage = [
                self.chain_id.to_be_bytes().as_ref(),
                chunk.prev_state_root.as_bytes(),
                chunk.post_state_root.as_bytes(),
                chunk.withdraw_root.as_bytes(),
                chunk.data_hash.as_bytes(),
                challenge_point_preimage[0].as_slice(),
                challenge_point_preimage[1].as_slice(),
                challenge_point_preimage[2].as_slice(),
                partial_result_preimage[0].as_slice(),
                partial_result_preimage[1].as_slice(),
                partial_result_preimage[2].as_slice(),
            ]
            .concat();
            res.push(chunk_public_input_hash_preimage)
        }

        // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
        let batch_data_hash_preimage = self
            .chunks_with_padding
            .iter()
            .take(self.number_of_valid_chunks)
            .flat_map(|x| x.data_hash.as_bytes().iter())
            .cloned()
            .collect();
        res.push(batch_data_hash_preimage);

        res
    }

    /// Compute the public inputs for this circuit, excluding the accumulator.
    /// Content: the public_input_hash
    pub(crate) fn instances_exclude_acc<F: Field>(&self) -> Vec<Vec<F>> {
        vec![self
            .public_input_hash
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64))
            .collect()]
    }
    //decompose cp and result to Fr be bytes
    pub(crate) fn decompose_cp_result(challenge_point: U256, result: U256) -> (Vec<[u8; 32]>,Vec<[u8; 32]>) {
        let cp_fe = Fp::from_bytes(&challenge_point.to_le_bytes()).unwrap();
        let cp = decompose_biguint::<Fr>(&fe_to_biguint(&cp_fe), 3, 88);
        let cp_preimage = cp.iter().map(|x| {let mut be_bytes = x.to_bytes(); be_bytes.reverse(); be_bytes}).collect::<Vec<_>>();
        let pr_fe = Fp::from_bytes(&result.to_le_bytes()).unwrap();
        let re = decompose_biguint::<Fr>(&fe_to_biguint(&pr_fe), 3, 88);
        let re_preimage = re.iter().map(|x| {let mut be_bytes = x.to_bytes(); be_bytes.reverse(); be_bytes}).collect::<Vec<_>>();

        (cp_preimage, re_preimage)
    }

}
