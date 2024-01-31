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
use crate::{blob_circuit::BlobCircuit, util::SubCircuit};
use rand::rngs::OsRng;

use crate::blob_circuit::util::*;

#[test]
fn test_blob_consistency(){
    let batch_commit = Fr::random(OsRng);

    let challenge_point = Fp::random(OsRng);
    let blob: Vec<Fp> = (0..4096)
        .map(|_| Fp::random(OsRng))
        .collect();

    println!("blob:{:?}",blob);

    // let omega = get_omega(4, 2);
    let omega = Fp::from(123).pow(&[(FP_S - 12) as u64, 0, 0, 0]);

    let result = poly_eval(blob.clone(), challenge_point, omega);
    println!("real result:{}", result);


    let circuit = BlobCircuit::<Fr> {
        batch_commit: batch_commit,
        challenge_point: challenge_point,
        index: 0,
        partial_blob: blob.clone(),
        partial_result: result,
        _marker: PhantomData,
    };    

    let instance = circuit.instance();

    let prover = match MockProver::<Fr>::run(20, &circuit, instance) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };

    assert_eq!(prover.verify(), Ok(()));
}



