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
    println!("omega:{}", omega);
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

#[test]
fn test_partial_blob_consistency(){
    let batch_commit = Fr::random(OsRng);

    // test blob[50] to blob[53]
    let blob: Vec<Fp> = (50..54)
        .map(|_| Fp::random(OsRng))
        .collect();
    
    log::trace!("blob:{:?}", blob);

    let index = 50;
    let omega = Fp::from(123).pow(&[(FP_S - 12) as u64, 0, 0, 0]);
    let roots_of_unity: Vec<_> = (0..4096)
        .map(|i| omega.pow(&[i as u64, 0, 0, 0]))
        .collect();
    let roots_of_unity_brp = bit_reversal_permutation(roots_of_unity); 

    //let challenge_point = roots_of_unity_brp[0];
    let challenge_point = Fp::random(OsRng);

    let result = poly_eval_partial(blob.clone(), challenge_point, omega, index);
    
    log::trace!("real result:{}", result);


    let circuit = BlobCircuit::<Fr> {
        batch_commit: batch_commit,
        challenge_point: challenge_point,
        index: index,
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

#[test]
fn test_txs_to_blob() {
    // Create some dummy transactions
    let txs: Vec<Vec<u8>> = vec![
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
    ];

    // Call the function under test
    let result = txs_to_blob(txs.clone()).ok().unwrap();
    for chunk in result.chunks(32) {
        println!("chunk:{:?}", chunk);
        Fp::from_bytes(chunk.try_into().unwrap()).unwrap();
    }
}

