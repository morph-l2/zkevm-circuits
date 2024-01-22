use halo2_base::QuantumCell::{Constant, self};
use halo2_base::gates::flex_gate::FlexGateConfig;
use halo2_base::utils::fe_to_biguint;
//use halo2_base::::{RangeInstructions, GateInstructions};
use halo2_base::{
    utils::ScalarField,
    Context, 
    AssignedValue,     
    gates::{
        range::{RangeConfig, RangeStrategy},
        GateInstructions, RangeInstructions,
    },
};
use halo2_proofs::circuit::Value;

use halo2_ecc::bigint::CRTInteger;

use halo2_ecc::fields::FieldChip;

use halo2_ecc::fields::fp::FpConfig;
use bls12_381::Scalar as Fp;
use eth_types::{Field, ToScalar, U256};

// assumption: LIMB_BITS >= 85
pub const LIMB_BITS: usize = 88;
pub const NUM_LIMBS: usize = 3;

// update this when FP is changed, e.g. 255 for BLS12-381 Scalar Field
const FP_MODULUS_BITS: usize = 254;
const FR_MODULUS_BITS: usize = 254;

// power of the largest power of two root of unity in Fp
// For BLS12-381, S = 32
//
// For BN254::Fq, S = 1, however, we need it to be higher than BLOB_WIDTH_BITS
// so we just set it to S = 32 for the test purposes. 
pub const FP_S: u32 = 32;

// pub fn decompose_to_lo_hi<F: Field>(
//     ctx: &mut Context<F>,
//     range: &RangeConfig<F>,
//     x: F,
// ) -> (AssignedValue<F>, AssignedValue<F>) {

//     //let x_limbs = halo2_base::utils::decompose(&x, NUM_LIMBS, LIMB_BITS);

//     let x_limbs = halo2_base::utils::decompose_biguint(&fe_to_biguint(&x), NUM_LIMBS, LIMB_BITS);

//     let x_lo =
//         range.gate.load_witness(ctx, Value::known(x_limbs[0] + x_limbs[1] * (F::from(2).pow(&[LIMB_BITS as u64, 0, 0, 0]))));

//     range.range_check(ctx, &x_lo.clone(), LIMB_BITS * 2);

//     let x_hi = range.gate.load_witness(ctx, Value::known(x_limbs[2]));

//     range.range_check(ctx, &x_hi.clone(), FR_MODULUS_BITS - LIMB_BITS * 2);

//     let mut sum = range.gate.mul(
//         ctx,
//         QuantumCell::Existing(x_hi),
//         Constant(F::from(2).pow(&[LIMB_BITS as u64 * 2, 0, 0, 0])),
//     );
//     sum = range.gate.add(ctx, QuantumCell::Existing(sum), QuantumCell::Existing(x_lo));

//     ctx.constrain_equal(&sum, );

//     (x_lo, x_hi)
// }

pub fn decompose_lo<F: Field>(
    x: F
) -> F {
    let x_limbs = halo2_base::utils::decompose_biguint::<F>(&fe_to_biguint(&x), NUM_LIMBS, LIMB_BITS);

    x_limbs[0] + x_limbs[1] * (F::from(2).pow(&[LIMB_BITS as u64, 0, 0, 0]))
}

pub fn decompose_hi<F: Field>(
    x: F
) -> F {
    let x_limbs = halo2_base::utils::decompose_biguint::<F>(&fe_to_biguint(&x), NUM_LIMBS, LIMB_BITS);

    x_limbs[2]
}

pub fn decompose_to_lo_hi<F: Field>(
    ctx: &mut Context<F>,
    range: &RangeConfig<F>,
    x: AssignedValue<F>,
) -> (AssignedValue<F>, AssignedValue<F>) {

    let x_lo =
        range.gate.load_witness(ctx, x.value().copied().map(|x| decompose_lo(x)));

    range.range_check(ctx, &x_lo.clone(), LIMB_BITS * 2);

    let x_hi = range.gate.load_witness(ctx, x.value().copied().map(|x| decompose_hi(x)));

    range.range_check(ctx, &x_hi.clone(), FR_MODULUS_BITS - LIMB_BITS * 2);

    let mut sum = range.gate.mul(
        ctx,
        QuantumCell::Existing(x_hi),
        Constant(F::from(2).pow(&[LIMB_BITS as u64 * 2, 0, 0, 0])),
    );
    sum = range.gate.add(ctx, QuantumCell::Existing(sum), QuantumCell::Existing(x_lo));

    ctx.constrain_equal(&sum, &x);

    (x_lo, x_hi)
}

pub fn to_bytes<F: Field>(
    x: F
) -> [u8;32] {
    x.to_repr().as_ref().to_vec().as_slice()[0..31].try_into().unwrap()
}


pub fn cross_field_load_private<F: Field>(
    ctx: &mut Context<F>,
    fq_chip: &FpConfig<F, Fp>,
    range: &RangeConfig<F>,
    x_lo: &AssignedValue<F>,
    x_hi: &AssignedValue<F>,
) -> CRTInteger<F> {

    let x_lo_fp = x_lo.value().copied().map(|x| Fp::from_bytes(&to_bytes(x)).unwrap());

    let x_hi_fp = x_hi.value().copied().map(|x| Fp::from_bytes(&to_bytes(x)).unwrap() * Fp::from(2).pow(&[(LIMB_BITS * 2) as u64, 0, 0, 0]));

    let x_fp = x_lo_fp * x_hi_fp;

    range.range_check(ctx, &x_lo.clone(), LIMB_BITS * 2);
    range.range_check(ctx, &x_hi.clone(), FP_MODULUS_BITS - LIMB_BITS * 2);

    let x_fp = fq_chip.load_private(ctx, FpConfig::<F, Fp>::fe_to_witness(&x_fp));
    cross_field_constrain_equal(ctx, &fq_chip.range().gate, x_lo, x_hi, &x_fp);
    x_fp
}

/*
given x_fp, a ProperCrtUint<Fp> in the target field Fp,
and its decomposition x_lo and x_hi in the native field F,
constrains x_lo and x_hi to be equal to the decomposition of x_fp
*/
pub fn cross_field_constrain_equal<F: Field>(
    ctx: &mut Context<F>,
    gate: &FlexGateConfig<F>,
    x_lo: &AssignedValue<F>,
    x_hi: &AssignedValue<F>,
    x_fp: &CRTInteger<F>,
) {
    let x_fp_limbs = x_fp.limbs();

    // check x_lo
    let mut sum = gate.load_zero(ctx);
    let mut mul = gate.load_constant(ctx, F::from(1));
    let limb_multiplier = gate.load_constant(ctx, F::from_u128(2u128.pow(LIMB_BITS as u32)));
    for i in 0..2 {
        let limb = x_fp_limbs[i];
        sum = gate.mul_add(ctx, QuantumCell::Existing(limb.clone()), QuantumCell::Existing(mul), QuantumCell::Existing(sum));
        mul = gate.mul(ctx, QuantumCell::Existing(limb_multiplier), QuantumCell::Existing(mul));
    }
    ctx.constrain_equal(&sum, &x_lo);

    //check x_hi
    let mut sum = gate.load_zero(ctx);
    let mut mul = gate.load_constant(ctx, F::from(1));
    let limb_multiplier = gate.load_constant(ctx, F::from_u128(2u128.pow(LIMB_BITS as u32)));
    for i in 2..NUM_LIMBS {
        let limb = x_fp_limbs[i];
        sum = gate.mul_add(ctx, QuantumCell::Existing(limb.clone()), QuantumCell::Existing(mul), QuantumCell::Existing(sum));
        mul = gate.mul(ctx, QuantumCell::Existing(limb_multiplier), QuantumCell::Existing(mul));
    }
    ctx.constrain_equal(&sum, &x_hi);
}

/*
given x_fp, a ProperCrtUint<Fp> in the target field Fp,
returns an AssignedValue 1 if x_fp is zero, and 0 otherwise.
*/
pub fn fp_is_zero<F: Field>(
    ctx: &mut Context<F>,
    gate: &FlexGateConfig<F>,
    x_fp: &CRTInteger<F>,
) -> AssignedValue<F> {
    let zero = gate.load_zero(ctx);
    let x_fp_limbs = x_fp.limbs();
    let mut partial_and = gate.load_constant(ctx, F::from(1));
    for limb in x_fp_limbs {
        let is_zero_limb = gate.is_equal(ctx, QuantumCell::Existing(limb.clone()), QuantumCell::Existing(zero));
        partial_and = gate.and(ctx, QuantumCell::Existing(is_zero_limb), Constant(F::from(1)));
    }
    partial_and
}

/*
raises x in Fp to the power of pow,
notice that pow is a constant
*/
pub fn fp_pow<F: Field>(
    ctx: &mut Context<F>,
    fp_chip: &FpConfig<F, Fp>,
    x: &CRTInteger<F>,
    pow: u32,
) -> CRTInteger<F> {
    if pow == 0 {
        return fp_chip.load_constant(ctx, fe_to_biguint(&Fp::one()));
    } else if pow == 1 {
        return x.clone();
    }

    let mut result = fp_pow(ctx, fp_chip, x, pow / 2);
    result = fp_chip.mul(ctx, &result.clone(), &result);
    if pow % 2 == 1 {
        result = fp_chip.mul(ctx, &result, &x.clone());
    }
    result
}


/*
returns a clone of the input vector with indices bit-reversed
*/
pub fn bit_reversal_permutation<T: Clone>(seq: Vec<T>) -> Vec<T> {
    // return a permutation of seq, where the indices are bit-reversed
    // e.g. bit_reversal_permutation([0, 1, 2, 3]) = [0, 2, 1, 3]
    let n = seq.len();
    let log_n = (n as f64).log2() as usize;
    let mut result: Vec<T> = vec![seq[0].clone(); n];
    for i in 0..n {
        let mut j = i;
        let mut k = 0;
        for _ in 0..log_n {
            k = (k << 1) | (j & 1);
            j >>= 1;
        }
        result[i] = seq[k].clone();
    }
    result
}
