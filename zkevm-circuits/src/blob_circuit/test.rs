use eth_types::{
    sign_types::{sign, SignData},
    Field,
};
use halo2_base::utils::fe_to_biguint;
use halo2_proofs::{
    arithmetic::Field as HaloField, circuit, dev::MockProver, halo2curves::{
        bn256::Fr,
        group::Curve,
        secp256k1::{self, Secp256k1Affine},
    }
};
use rand::{Rng, RngCore};
use std::marker::PhantomData;
use bls12_381::{Scalar as Fp};
use crate::{blob_circuit::BlobCircuit, util::SubCircuit, witness::CircuitBlob};
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
    println!("omega:{}", omega);
    let result = poly_eval(blob.clone(), challenge_point, omega);
    println!("real result:{}", result);

    let circuit_blob = CircuitBlob::<Fr>::new(challenge_point, 0, blob.clone(), result);

    let circuit = BlobCircuit::<Fr> {
        blob:circuit_blob,
        _marker: PhantomData,
    };    

    let instance = circuit.instance();

    let prover = match MockProver::<Fr>::run(19, &circuit, instance) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };

    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_partial_blob_consistency(){
    let batch_commit = Fr::random(OsRng);

    let blob: Vec<Fp> = (0..51)
        .map(|_| Fp::random(OsRng))
        .collect();
    

    log::trace!("blob:{:?}", blob);

    let index = 0;
    let omega = Fp::from(123).pow(&[(FP_S - 12) as u64, 0, 0, 0]);
    let roots_of_unity: Vec<_> = (0..4096)
        .map(|i| omega.pow(&[i as u64, 0, 0, 0]))
        .collect();
    let roots_of_unity_brp = bit_reversal_permutation(roots_of_unity); 

    //let challenge_point = roots_of_unity_brp[0];
    //let challenge_point = Fp::random(OsRng);
    let challenge_point = Fp::from(128);

    let result = poly_eval_partial(blob.clone(), challenge_point, omega, index);
    
    log::trace!("real result:{}", result);

    let circuit_blob = CircuitBlob::<Fr>::new(challenge_point, index, blob.clone(), result);

    let circuit = BlobCircuit::<Fr> {
        blob:circuit_blob,
        _marker: PhantomData::default(),
    };    

    let instance = circuit.instance();

    let prover = match MockProver::<Fr>::run(20, &circuit, instance) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };

    assert_eq!(prover.verify(), Ok(()));
}



