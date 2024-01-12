//! blob_consistency works as follows:

use rand::{rngs::OsRng, Rng};
use crate::util::*;

use halo2_base::{
    gates::RangeChip,
    utils::ScalarField,
    AssignedValue, Context,
};
use halo2_ecc::fields::{fp::FpChip, FieldChip};
use poseidon::PoseidonChip;

// poseidon hash params
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

/// BLOB_WIDTH must be a power of two
pub const BLOB_WIDTH: usize = 4096;
/// BLOB_WIDTH_BITS
pub const BLOB_WIDTH_BITS: u32 = 12;
/// degree
pub const K: usize = 14;
/// LOOKUP_BITS
pub const LOOKUP_BITS: usize = 10;

/// check blob consistency with x,y
pub fn blob_consistency_check_gadget<F: ScalarField, Fp: ScalarField>(
    ctx: &mut Context<F>,
    input: CircuitInput<F, Fp>,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let zero = ctx.load_zero();
    let range = RangeChip::<F>::default(LOOKUP_BITS);
    let gate = &range.gate;

    let fp_chip = FpChip::<F, Fp>::new(&range, LIMB_BITS, NUM_LIMBS);
    let one_fp = fp_chip.load_constant(ctx, Fp::one());

    // ==== STEP 1: calculate the challenge point ====
    //
    // challenge_point = poseidon(batch_commit, blob[0..BLOB_WIDTH])
    //
    // REMARK: notice that it is important to include the blob in the
    // poseidon hash, otherwise we have a soundness bug.
    //
    let batch_commit = input.batch_commit;
    let batch_commit = ctx.load_witness(batch_commit);
    make_public.push(batch_commit);

    let blob = input
        .blob
        .iter()
        .map(|x| fp_chip.load_private(ctx, *x))
        .collect::<Vec<_>>();

    let mut poseidon = PoseidonChip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();
    poseidon.update(&[batch_commit]);
    for item in blob.clone() {
        poseidon.update(item.limbs());
    }

    let challenge_point = poseidon.squeeze(ctx, gate).unwrap();
    make_public.push(challenge_point.clone());

    // === STEP 2: compute the barycentric formula ===
    // spec reference:
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md
    //
    // barycentric formula:
    // Evaluate a polynomial (in evaluation form) at an arbitrary point ``z``.
    // - When ``z`` is in the domain, the evaluation can be found by indexing
    // the polynomial at the position that ``z`` is in the domain.
    // - When ``z`` is not in the domain, the barycentric formula is used:
    //    f(z) = ((z**WIDTH - 1) / WIDTH) *  sum_(i=0)^WIDTH  (f(DOMAIN[i]) * DOMAIN[i]) / (z - DOMAIN[i])
    //
    // In our case:
    // - ``z`` is the challenge point in Fp
    // - ``WIDTH`` is BLOB_WIDTH
    // - ``DOMAIN`` is the bit_reversal_permutation roots of unity
    // - ``f(DOMAIN[i])`` is the blob[i]

    // load challenge_point to fp_chip
    let (cp_lo, cp_hi) = decompose_to_lo_hi(ctx, &range, challenge_point);
    let challenge_point_fp = cross_field_load_private(ctx, &fp_chip, &range, &cp_lo, &cp_hi);

    // loading roots of unity to fp_chip as constants
    let blob_width_th_root_of_unity =
        Fp::from(123).pow(&[(FP_S - BLOB_WIDTH_BITS) as u64, 0, 0, 0]);
    let roots_of_unity: Vec<_> = (0..BLOB_WIDTH)
        .map(|i| blob_width_th_root_of_unity.pow(&[i as u64, 0, 0, 0]))
        .collect();
    let roots_of_unity = roots_of_unity
        .iter()
        .map(|x| fp_chip.load_constant(ctx, *x))
        .collect::<Vec<_>>();

    // apply bit_reversal_permutation to roots_of_unity
    // spec reference:
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#bit-reversal-permutation
    //
    let roots_of_unity_brp = bit_reversal_permutation(roots_of_unity);

    let mut result = fp_chip.load_constant(ctx, Fp::zero());
    let mut cp_is_not_root_of_unity = fp_chip.load_constant(ctx, Fp::one());
    let mut barycentric_evaluation = fp_chip.load_constant(ctx, Fp::zero());
    for i in 0..BLOB_WIDTH as usize {
        let numinator_i = fp_chip.mul(ctx, roots_of_unity_brp[i].clone(), blob[i].clone());

        let denominator_i_no_carry = fp_chip.sub_no_carry(
            ctx,
            challenge_point_fp.clone(),
            roots_of_unity_brp[i].clone(),
        );
        let denominator_i = fp_chip.carry_mod(ctx, denominator_i_no_carry);

        // avoid division by zero
        // safe_denominator_i = denominator_i       (denominator_i != 0)
        // safe_denominator_i = 1                   (denominator_i == 0)
        let is_zero_denominator_i = fp_is_zero(ctx, gate, &denominator_i);
        let is_zero_denominator_i =
            cross_field_load_private(ctx, &fp_chip, &range, &is_zero_denominator_i, &zero);
        let safe_denominator_i =
            fp_chip.add_no_carry(ctx, denominator_i, is_zero_denominator_i.clone());
        let safe_denominator_i = fp_chip.carry_mod(ctx, safe_denominator_i);

        // update `cp_is_not_root_of_unity`
        // cp_is_not_root_of_unity = 1          (initialize)
        // cp_is_not_root_of_unity = 0          (denominator_i == 0)
        let non_zero_denominator_i =
            fp_chip.sub_no_carry(ctx, one_fp.clone(), is_zero_denominator_i.clone());
        cp_is_not_root_of_unity = fp_chip.mul(ctx, cp_is_not_root_of_unity, non_zero_denominator_i);

        // update `result`
        // result = blob[i]     (challenge_point = roots_of_unity_brp[i])
        let select_blob_i = fp_chip.mul(ctx, blob[i].clone(), is_zero_denominator_i.clone());
        let tmp_result = fp_chip.add_no_carry(ctx, result, select_blob_i);
        result = fp_chip.carry_mod(ctx, tmp_result);

        let term_i = fp_chip.divide(ctx, numinator_i, safe_denominator_i);
        let evaluation_not_proper = fp_chip.add_no_carry(ctx, barycentric_evaluation, term_i);
        barycentric_evaluation = fp_chip.carry_mod(ctx, evaluation_not_proper);
    }
    let cp_to_the_width = fp_pow(ctx, &fp_chip, &challenge_point_fp, BLOB_WIDTH as u32);
    let cp_to_the_width_minus_one = fp_chip.sub_no_carry(ctx, cp_to_the_width, one_fp);
    let cp_to_the_width_minus_one = fp_chip.carry_mod(ctx, cp_to_the_width_minus_one);
    let width_fp = fp_chip.load_constant(ctx, Fp::from(BLOB_WIDTH as u64));
    let factor = fp_chip.divide(ctx, cp_to_the_width_minus_one, width_fp);
    barycentric_evaluation = fp_chip.mul(ctx, barycentric_evaluation, factor);

    // === STEP 3: select between the two case ===
    // if challenge_point is a root of unity, then result = blob[i]
    // else result = barycentric_evaluation
    let select_evaluation = fp_chip.mul(ctx, barycentric_evaluation, cp_is_not_root_of_unity);
    let tmp_result = fp_chip.add_no_carry(ctx, result, select_evaluation);
    result = fp_chip.carry_mod(ctx, tmp_result);
    make_public.extend(result.limbs());
}

/// check chunk blob consistency with x,y
pub fn partial_blob_consistency_check_gadget<F: ScalarField, Fp: ScalarField>(
    ctx: &mut Context<F>,
    input: PartialCircuitInput<F, Fp>,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let zero = ctx.load_zero();
    let range = RangeChip::<F>::default(LOOKUP_BITS);
    let gate = &range.gate;

    let fp_chip = FpChip::<F, Fp>::new(&range, LIMB_BITS, NUM_LIMBS);
    let one_fp = fp_chip.load_constant(ctx, Fp::one());

    // ==== STEP 1: calculate the challenge point ====
    //
    // challenge_point = poseidon(batch_commit, blob[0..BLOB_WIDTH])
    //
    // REMARK: notice that it is important to include the blob in the
    // poseidon hash, otherwise we have a soundness bug.
    //
    let batch_commit = input.batch_commit;
    let batch_commit = ctx.load_witness(batch_commit);
    make_public.push(batch_commit);

    let blob = input
        .partial_blob
        .iter()
        .map(|x| fp_chip.load_private(ctx, *x))
        .collect::<Vec<_>>();

    let challenge_point = input.challenge_point;
    let challenge_point = ctx.load_witness(challenge_point);
    make_public.push(challenge_point.clone());

    // === STEP 2: compute the barycentric formula ===
    // spec reference:
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md
    //
    // barycentric formula:
    // Evaluate a polynomial (in evaluation form) at an arbitrary point ``z``.
    // - When ``z`` is in the domain, the evaluation can be found by indexing
    // the polynomial at the position that ``z`` is in the domain.
    // - When ``z`` is not in the domain, the barycentric formula is used:
    //    f(z) = ((z**WIDTH - 1) / WIDTH) *  sum_(i=0)^WIDTH  (f(DOMAIN[i]) * DOMAIN[i]) / (z - DOMAIN[i])
    //
    // In our case:
    // - ``z`` is the challenge point in Fp
    // - ``WIDTH`` is BLOB_WIDTH
    // - ``DOMAIN`` is the bit_reversal_permutation roots of unity
    // - ``f(DOMAIN[i])`` is the blob[i]

    // load challenge_point to fp_chip
    let (cp_lo, cp_hi) = decompose_to_lo_hi(ctx, &range, challenge_point);
    let challenge_point_fp = cross_field_load_private(ctx, &fp_chip, &range, &cp_lo, &cp_hi);

    // loading roots of unity to fp_chip as constants
    let blob_width_th_root_of_unity =
        Fp::from(123).pow(&[(FP_S - BLOB_WIDTH_BITS) as u64, 0, 0, 0]);
    let roots_of_unity: Vec<_> = (0..32)
        .map(|i| blob_width_th_root_of_unity.pow(&[i as u64, 0, 0, 0]))
        .collect();
    let roots_of_unity = roots_of_unity
        .iter()
        .map(|x| fp_chip.load_constant(ctx, *x))
        .collect::<Vec<_>>();

    // apply bit_reversal_permutation to roots_of_unity
    // spec reference:
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#bit-reversal-permutation
    //
    let roots_of_unity_brp = bit_reversal_permutation(roots_of_unity);

    let mut result = fp_chip.load_constant(ctx, Fp::zero());
    let mut cp_is_not_root_of_unity = fp_chip.load_constant(ctx, Fp::one());
    let mut barycentric_evaluation = fp_chip.load_constant(ctx, Fp::zero());
    for i in 0..32 {
        let numinator_i = fp_chip.mul(ctx, roots_of_unity_brp[i].clone(), blob[i].clone());

        let denominator_i_no_carry = fp_chip.sub_no_carry(
            ctx,
            challenge_point_fp.clone(),
            roots_of_unity_brp[i].clone(),
        );
        let denominator_i = fp_chip.carry_mod(ctx, denominator_i_no_carry);

        // avoid division by zero
        // safe_denominator_i = denominator_i       (denominator_i != 0)
        // safe_denominator_i = 1                   (denominator_i == 0)
        let is_zero_denominator_i = fp_is_zero(ctx, gate, &denominator_i);
        let is_zero_denominator_i =
            cross_field_load_private(ctx, &fp_chip, &range, &is_zero_denominator_i, &zero);
        let safe_denominator_i =
            fp_chip.add_no_carry(ctx, denominator_i, is_zero_denominator_i.clone());
        let safe_denominator_i = fp_chip.carry_mod(ctx, safe_denominator_i);

        // update `cp_is_not_root_of_unity`
        // cp_is_not_root_of_unity = 1          (initialize)
        // cp_is_not_root_of_unity = 0          (denominator_i == 0)
        let non_zero_denominator_i =
            fp_chip.sub_no_carry(ctx, one_fp.clone(), is_zero_denominator_i.clone());
        cp_is_not_root_of_unity = fp_chip.mul(ctx, cp_is_not_root_of_unity, non_zero_denominator_i);

        // update `result`
        // result = blob[i]     (challenge_point = roots_of_unity_brp[i])
        let select_blob_i = fp_chip.mul(ctx, blob[i].clone(), is_zero_denominator_i.clone());
        let tmp_result = fp_chip.add_no_carry(ctx, result, select_blob_i);
        result = fp_chip.carry_mod(ctx, tmp_result);

        let term_i = fp_chip.divide(ctx, numinator_i, safe_denominator_i);
        let evaluation_not_proper = fp_chip.add_no_carry(ctx, barycentric_evaluation, term_i);
        barycentric_evaluation = fp_chip.carry_mod(ctx, evaluation_not_proper);
    }
    let cp_to_the_width = fp_pow(ctx, &fp_chip, &challenge_point_fp, BLOB_WIDTH as u32);
    let cp_to_the_width_minus_one = fp_chip.sub_no_carry(ctx, cp_to_the_width, one_fp);
    let cp_to_the_width_minus_one = fp_chip.carry_mod(ctx, cp_to_the_width_minus_one);
    let width_fp = fp_chip.load_constant(ctx, Fp::from(BLOB_WIDTH as u64));
    let factor = fp_chip.divide(ctx, cp_to_the_width_minus_one, width_fp);
    barycentric_evaluation = fp_chip.mul(ctx, barycentric_evaluation, factor);

    // === STEP 3: select between the two case ===
    // if challenge_point is a root of unity, then result = blob[i]
    // else result = barycentric_evaluation
    let select_evaluation = fp_chip.mul(ctx, barycentric_evaluation, cp_is_not_root_of_unity);
    let tmp_result = fp_chip.add_no_carry(ctx, result, select_evaluation);
    result = fp_chip.carry_mod(ctx, tmp_result);
    make_public.extend(result.limbs());
}


/// Circuit input
#[derive(Clone, Debug)]
pub struct CircuitInput<F: ScalarField, Fp: ScalarField> {
    /// commit of batch
    pub batch_commit: F,
    /// blob element
    pub blob: [Fp; BLOB_WIDTH],
}

impl<F: ScalarField, Fp: ScalarField> Default for CircuitInput<F, Fp> {
    fn default() -> Self {
        Self {
            batch_commit: F::from(42),
            blob: [Fp::from(0); BLOB_WIDTH],
        }
    }
}

impl<F: ScalarField, Fp: ScalarField> CircuitInput<F, Fp> {
    /// generate random circuit input
    pub fn random() -> Self {
        CircuitInput { 
            batch_commit: F::random(OsRng), 
            blob: (0..BLOB_WIDTH)
            .map(|_| Fp::random(OsRng))
            .collect::<Vec<Fp>>()
            .try_into()
            .unwrap()
        }
    }
}

/// Partial Circuit input
#[derive(Clone, Debug)]
pub struct PartialCircuitInput<F: ScalarField, Fp: ScalarField> {
    /// commit of batch
    pub batch_commit: F,
    /// challenge point x
    pub challenge_point: F,
    /// index of blob element    
    pub index: usize,
    /// partial blob element    
    pub partial_blob: [Fp; 32],
}

impl<F: ScalarField, Fp: ScalarField> Default for PartialCircuitInput<F, Fp> {
    fn default() -> Self {
        Self {
            batch_commit: F::from(42),
            challenge_point: F::from(42),
            index:0,
            partial_blob: [Fp::from(0); 32],
        }
    }
}

impl<F: ScalarField, Fp: ScalarField> PartialCircuitInput<F, Fp> {
    /// generate random partial circuit input
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let blob_index: usize = rng.gen_range(0..128);
        PartialCircuitInput { 
            batch_commit: F::random(OsRng), 
            challenge_point: F::random(OsRng),
            index:blob_index,
            partial_blob: (0..32)
            .map(|_| Fp::random(OsRng))
            .collect::<Vec<Fp>>()
            .try_into()
            .unwrap()
        }
    }
}

// TODO: add more tests!
#[test]
fn test_random_blob_consistency_check_mock() {
    use std::env::set_var;
    use halo2_base::{
        gates::builder::{GateThreadBuilder, RangeWithInstanceCircuitBuilder},    
        halo2_proofs::{
            halo2curves::FieldExt,
            halo2curves::bn256::{Fq, Fr},
            arithmetic::Field,
            dev::MockProver,            
        },
        utils::{decompose_biguint, fe_to_biguint},
    };
    use poseidon_native::Poseidon;
    use bls12_381::Scalar;

    type BlobField = Scalar;

    // create a random input
    let input = CircuitInput::<Fr, BlobField>::random();

    // do the calculation outside of the circuit, to verify the result of the circuit
    let mut native_poseidon = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
    native_poseidon.update(&[input.batch_commit]);
    for item in input.blob.clone() {
        let item = fe_to_biguint(&item);
        let item_limbs = decompose_biguint::<Fr>(&item, NUM_LIMBS, LIMB_BITS);

        native_poseidon.update(item_limbs.as_slice());
    }

    let challenge_point = native_poseidon.squeeze();

    let challenge_point_fp = BlobField::from_bytes_le(challenge_point.to_bytes_le().as_slice());

    // Fq does not implement root_of_unity, i.e. unimplemented!()
    // Use the commented line for BLS12-381 Scalar Field
    // let blob_width_th_root_of_unity = BlobField::root_of_unity().pow(&[(BlobField::S - BLOB_WIDTH_BITS) as u64, 0, 0, 0]);
    let blob_width_th_root_of_unity =
        BlobField::from(123).pow(&[(FP_S - BLOB_WIDTH_BITS) as u64, 0, 0, 0]);

    let roots_of_unity: Vec<_> = (0..BLOB_WIDTH)
        .map(|i| blob_width_th_root_of_unity.pow(&[i as u64, 0, 0, 0]))
        .collect();
    let roots_of_unity_brp = bit_reversal_permutation(roots_of_unity);

    let mut result = BlobField::zero();
    let mut cp_is_root_of_unity = false;
    for (i, item) in roots_of_unity_brp.iter().enumerate() {
        if item == &challenge_point_fp {
            result = input.blob[i];
            cp_is_root_of_unity = true;
        }
    }
    if !cp_is_root_of_unity {
        let mut barycentric_evaluation = BlobField::zero();
        for i in 0..BLOB_WIDTH {
            let numinator_i = roots_of_unity_brp[i] * input.blob[i];
            let denominator_i = challenge_point_fp - roots_of_unity_brp[i];
            let term_i = numinator_i * denominator_i.invert().unwrap();

            barycentric_evaluation = barycentric_evaluation + term_i;
        }
        // evaluation = evaluation * (challenge_point**BLOB_WIDTH - 1) / BLOB_WIDTH
        let cp_to_the_width = challenge_point_fp.pow(&[BLOB_WIDTH as u64, 0, 0, 0]);
        let cp_to_the_width_minus_one = cp_to_the_width - BlobField::one();
        let width = BlobField::from(BLOB_WIDTH as u64);
        let factor = cp_to_the_width_minus_one * width.invert().unwrap();
        barycentric_evaluation = barycentric_evaluation * factor;

        result = barycentric_evaluation;
    }
    let result = fe_to_biguint(&result);
    let result_limbs = decompose_biguint::<Fr>(&result, NUM_LIMBS, LIMB_BITS);

    let mut public_input: Vec<Fr> = vec![input.batch_commit, challenge_point];
    public_input.extend(result_limbs.clone());

    // set the `LOOKUP_BITS` for halo2-lib
    set_var("LOOKUP_BITS", LOOKUP_BITS.to_string());

    let mut builder = GateThreadBuilder::<Fr>::mock();
    let ctx = builder.main(0);
    let mut make_public: Vec<AssignedValue<Fr>> = vec![];

    blob_consistency_check_gadget::<Fr, BlobField>(ctx, input, &mut make_public);

    builder.config(K, Some(20));
    let circuit = RangeWithInstanceCircuitBuilder::mock(builder, make_public.clone());

    MockProver::run(K as u32, &circuit, vec![public_input])
        .unwrap()
        .assert_satisfied();
}