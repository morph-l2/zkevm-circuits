//! Utility traits, functions used in the crate.
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    U256,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};
use halo2_base::QuantumCell::Constant;
use halo2_base::safe_types::{RangeInstructions, GateInstructions};
use halo2_base::{
    utils::ScalarField,
    Context, 
    safe_types::RangeChip, 
    AssignedValue, gates::GateChip,
};
use halo2_ecc::bigint::ProperCrtUint;
use halo2_ecc::fields::FieldChip;
use halo2_ecc::fields::fp::FpChip;


/// Returns the sum of the passed in cells
pub mod sum {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression for the sum of the list of expressions.
    pub fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(0.expr(), |acc, input| acc + input.expr())
    }

    /// Returns the sum of the given list of values within the field.
    pub fn value<F: FieldExt>(values: &[u8]) -> F {
        values
            .iter()
            .fold(F::zero(), |acc, value| acc + F::from(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod and {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that evaluates to 1 only if all the expressions in
    /// the given list are 1, else returns 0.
    pub fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(1.expr(), |acc, input| acc * input.expr())
    }

    /// Returns the product of all given values.
    pub fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::one(), |acc, input| acc * input)
    }
}

/// Returns `1` when `expr[0] || expr[1] || ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod or {
    use super::{and, not};
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that evaluates to 1 if any expression in the given
    /// list is 1. Returns 0 if all the expressions were 0.
    pub fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        not::expr(and::expr(inputs.into_iter().map(not::expr)))
    }

    /// Returns the value after passing all given values through the OR gate.
    pub fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        not::value(and::value(inputs.into_iter().map(not::value).collect()))
    }
}

/// Returns `1` when `b == 0`, and returns `0` otherwise.
/// `b` needs to be boolean
pub mod not {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that represents the NOT of the given expression.
    pub fn expr<F: FieldExt, E: Expr<F>>(b: E) -> Expression<F> {
        1.expr() - b.expr()
    }

    /// Returns a value that represents the NOT of the given value.
    pub fn value<F: FieldExt>(b: F) -> F {
        F::one() - b
    }
}

/// Returns `a ^ b`.
/// `a` and `b` needs to be boolean
pub mod xor {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that represents the XOR of the given expression.
    pub fn expr<F: FieldExt, E: Expr<F>>(a: E, b: E) -> Expression<F> {
        a.expr() + b.expr() - 2.expr() * a.expr() * b.expr()
    }

    /// Returns a value that represents the XOR of the given value.
    pub fn value<F: FieldExt>(a: F, b: F) -> F {
        a + b - F::from(2u64) * a * b
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub mod select {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns the `when_true` expression when the selector is true, else
    /// returns the `when_false` expression.
    pub fn expr<F: FieldExt>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
    }

    /// Returns the `when_true` value when the selector is true, else returns
    /// the `when_false` value.
    pub fn value<F: FieldExt>(selector: F, when_true: F, when_false: F) -> F {
        selector * when_true + (F::one() - selector) * when_false
    }

    /// Returns the `when_true` word when selector is true, else returns the
    /// `when_false` word.
    pub fn value_word<F: FieldExt>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::one() {
            when_true
        } else {
            when_false
        }
    }
}

/// Trait that implements functionality to get a constant expression from
/// commonly used types.
pub trait Expr<F: FieldExt> {
    /// Returns an expression for the type.
    fn expr(&self) -> Expression<F>;
}

/// Implementation trait `Expr` for type able to be casted to u64
#[macro_export]
macro_rules! impl_expr {
    ($type:ty) => {
        impl<F: halo2_proofs::arithmetic::FieldExt> $crate::util::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from(*self as u64))
            }
        }
    };
    ($type:ty, $method:path) => {
        impl<F: halo2_proofs::arithmetic::FieldExt> $crate::util::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from($method(self) as u64))
            }
        }
    };
}

impl_expr!(bool);
impl_expr!(u8);
impl_expr!(u64);
impl_expr!(usize);
impl_expr!(OpcodeId, OpcodeId::as_u8);
impl_expr!(GasCost, GasCost::as_u64);

impl<F: FieldExt> Expr<F> for Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        self.clone()
    }
}

impl<F: FieldExt> Expr<F> for &Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        (*self).clone()
    }
}

impl<F: FieldExt> Expr<F> for i32 {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(
            F::from(self.unsigned_abs() as u64)
                * if self.is_negative() {
                    -F::one()
                } else {
                    F::one()
                },
        )
    }
}

/// Given a bytes-representation of an expression, it computes and returns the
/// single expression.
pub fn expr_from_bytes<F: FieldExt, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
    let mut value = 0.expr();
    let mut multiplier = F::one();
    for byte in bytes.iter() {
        value = value + byte.expr() * multiplier;
        multiplier *= F::from(256);
    }
    value
}

/// Given a u16-array-representation of an expression, it computes and returns
/// the single expression.
pub fn expr_from_u16<F: FieldExt, E: Expr<F>>(u16s: &[E]) -> Expression<F> {
    let mut value = 0.expr();
    let mut multiplier = F::one();
    for u16 in u16s.iter() {
        value = value + u16.expr() * multiplier;
        multiplier *= F::from(2u64.pow(16));
    }
    value
}

/// Returns 2**by as FieldExt
pub fn pow_of_two<F: FieldExt>(by: usize) -> F {
    F::from(2).pow(&[by as u64, 0, 0, 0])
}

/// Returns tuple consists of low and high part of U256
pub fn split_u256(value: &U256) -> (U256, U256) {
    (
        U256([value.0[0], value.0[1], 0, 0]),
        U256([value.0[2], value.0[3], 0, 0]),
    )
}

/// Split a U256 value into 4 64-bit limbs stored in U256 values.
pub fn split_u256_limb64(value: &U256) -> [U256; 4] {
    [
        U256([value.0[0], 0, 0, 0]),
        U256([value.0[1], 0, 0, 0]),
        U256([value.0[2], 0, 0, 0]),
        U256([value.0[3], 0, 0, 0]),
    ]
}

/// assumption: LIMB_BITS >= 85
pub const LIMB_BITS: usize = 88;
/// 3 LIMBS
pub const NUM_LIMBS: usize = 3;

// update this when FP is changed, e.g. 255 for BLS12-381 Scalar Field
const FP_MODULUS_BITS: usize = 254;
const FR_MODULUS_BITS: usize = 254;

/// power of the largest power of two root of unity in Fp
/// For BLS12-381, S = 32
//
/// For BN254::Fq, S = 1, however, we need it to be higher than BLOB_WIDTH_BITS
/// so we just set it to S = 32 for the test purposes. 
pub const FP_S: u32 = 32;

/// decompose x to lo hi
pub fn decompose_to_lo_hi<F: ScalarField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    x: AssignedValue<F>,
) -> (AssignedValue<F>, AssignedValue<F>) {
    let x_limbs = halo2_base::utils::decompose(x.value(), NUM_LIMBS, LIMB_BITS);

    let x_lo =
        ctx.load_witness(x_limbs[0] + x_limbs[1] * F::from(2).pow(&[LIMB_BITS as u64, 0, 0, 0]));
    range.range_check(ctx, x_lo.clone(), LIMB_BITS * 2);

    let x_hi = ctx.load_witness(x_limbs[2]);
    range.range_check(ctx, x_hi.clone(), FR_MODULUS_BITS - LIMB_BITS * 2);

    let mut sum = range.gate.mul(
        ctx,
        x_hi,
        Constant(F::from(2).pow(&[LIMB_BITS as u64 * 2, 0, 0, 0])),
    );
    sum = range.gate.add(ctx, sum, x_lo);
    ctx.constrain_equal(&sum, &x);

    (x_lo, x_hi)
}


/// given two AssignedValue<F>, x_lo and x_hi, in the native field F,
/// returns a ProperCrtUint<F> in the target field Fp (which is bigger)

pub fn cross_field_load_private<F: ScalarField, Fp: ScalarField>(
    ctx: &mut Context<F>,
    fq_chip: &FpChip<F, Fp>,
    range: &RangeChip<F>,
    x_lo: &AssignedValue<F>,
    x_hi: &AssignedValue<F>,
) -> ProperCrtUint<F> {
    let x_fp = Fp::from_bytes_le(x_lo.value().to_bytes_le().as_slice())
        + Fp::from_bytes_le(x_hi.value().to_bytes_le().as_slice())
            * Fp::from(2).pow(&[(LIMB_BITS * 2) as u64, 0, 0, 0]);

    range.range_check(ctx, x_lo.clone(), LIMB_BITS * 2);
    range.range_check(ctx, x_hi.clone(), FP_MODULUS_BITS - LIMB_BITS * 2);

    let x_fp = fq_chip.load_private(ctx, x_fp);
    cross_field_constrain_equal(ctx, &fq_chip.range().gate, x_lo, x_hi, &x_fp);
    x_fp
}


/// given x_fp, a ProperCrtUint<Fp> in the target field Fp,
/// and its decomposition x_lo and x_hi in the native field F,
/// constrains x_lo and x_hi to be equal to the decomposition of x_fp
pub fn cross_field_constrain_equal<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    x_lo: &AssignedValue<F>,
    x_hi: &AssignedValue<F>,
    x_fp: &ProperCrtUint<F>,
) {
    let x_fp_limbs = x_fp.limbs();

    // check x_lo
    let mut sum = ctx.load_zero();
    let mut mul = ctx.load_constant(F::from(1));
    let limb_multiplier = ctx.load_constant(F::from_u128(2u128.pow(LIMB_BITS as u32)));
    for i in 0..2 {
        let limb = x_fp_limbs[i];
        sum = gate.mul_add(ctx, limb.clone(), mul, sum);
        mul = gate.mul(ctx, limb_multiplier, mul);
    }
    ctx.constrain_equal(&sum, &x_lo);

    //check x_hi
    let mut sum = ctx.load_zero();
    let mut mul = ctx.load_constant(F::from(1));
    let limb_multiplier = ctx.load_constant(F::from_u128(2u128.pow(LIMB_BITS as u32)));
    for i in 2..NUM_LIMBS {
        let limb = x_fp_limbs[i];
        sum = gate.mul_add(ctx, limb.clone(), mul, sum);
        mul = gate.mul(ctx, limb_multiplier, mul);
    }
    ctx.constrain_equal(&sum, &x_hi);
}


/// given x_fp, a ProperCrtUint<Fp> in the target field Fp,
/// returns an AssignedValue 1 if x_fp is zero, and 0 otherwise.

pub fn fp_is_zero<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    x_fp: &ProperCrtUint<F>,
) -> AssignedValue<F> {
    let zero = ctx.load_zero();
    let x_fp_limbs = x_fp.limbs();
    let mut partial_and = ctx.load_constant(F::from(1));
    for limb in x_fp_limbs {
        let is_zero_limb = gate.is_equal(ctx, limb.clone(), zero);
        partial_and = gate.and(ctx, is_zero_limb, Constant(F::from(1)));
    }
    partial_and
}


/// raises x in Fp to the power of pow,
/// notice that pow is a constant

pub fn fp_pow<F: ScalarField, Fp: ScalarField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<F, Fp>,
    x: &ProperCrtUint<F>,
    pow: u32,
) -> ProperCrtUint<F> {
    if pow == 0 {
        return fp_chip.load_constant(ctx, Fp::one());
    } else if pow == 1 {
        return x.clone();
    }

    let mut result = fp_pow(ctx, fp_chip, x, pow / 2);
    result = fp_chip.mul(ctx, result.clone(), result);
    if pow % 2 == 1 {
        result = fp_chip.mul(ctx, result, x.clone());
    }
    result
}



/// returns a clone of the input vector with indices bit-reversed
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