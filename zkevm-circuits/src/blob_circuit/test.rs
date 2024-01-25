use eth_types::{
    sign_types::{sign, SignData},
    Field,
};
use halo2_base::utils::fe_to_biguint;
use halo2_proofs::{
    arithmetic::Field as HaloField,
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        group::Curve,
        secp256k1::{self, Secp256k1Affine},
    },
};
use rand::{Rng, RngCore};
use std::marker::PhantomData;
use bls12_381::Scalar as Fp;
use crate::blob_circuit::BlobCircuit;
use rand::rngs::OsRng;

use crate::blob_circuit::util::*;

#[test]
fn test_blob_consistency(){
    let batch_commit = Fr::random(OsRng);
    let challenge_point = Fp::random(OsRng);
    let blob: Vec<Fp> = (0..4)
        .map(|_| Fp::random(OsRng))
        .collect();

    let omega = get_omega(4, 2);
    
    let result = poly_eval(blob.clone(), challenge_point, omega);

    // let y_limbs = halo2_base::utils::decompose_biguint::<Fr>(&fe_to_biguint(&result), NUM_LIMBS, LIMB_BITS);

    let circuit = BlobCircuit::<Fr> {
        batch_commit: batch_commit,
        challenge_point: challenge_point,
        index: 0,
        partial_blob: blob.clone(),
        partial_result: result,
        _marker: PhantomData,
    };    

    let prover = match MockProver::<Fr>::run(20, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };

    assert_eq!(prover.verify(), Ok(()));
}



