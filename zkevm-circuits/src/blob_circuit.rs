use halo2_base::{
    Context,
    utils::{
        ScalarField, bigint_to_fe, biguint_to_fe, bit_length, decompose_bigint_option, decompose_biguint,
        fe_to_biguint, fe_to_bigint, modulus,}, 
    gates::{range::{self, RangeConfig}, GateInstructions}
};

use halo2_ecc::fields::{fp::{FpConfig, FpStrategy}, FieldChip};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Circuit, Expression},
};

use bls12_381::Scalar as Fp;
use crate::{util::{SubCircuit, Challenges, SubCircuitConfig}, witness::Block};
use std::{marker::PhantomData, ops::Add};
use eth_types::{Field, ToScalar, U256};
use rand::{rngs::OsRng, Rng};
mod util;

use util::*;

// BLOB_WIDTH must be a power of two
pub const BLOB_WIDTH: usize = 4096;
pub const BLOB_WIDTH_BITS: u32 = 12;

pub const K: usize = 14;
pub const LOOKUP_BITS: usize = 10;


#[derive(Clone, Debug)]
pub struct BlobCircuitConfigArgs<F: Field> {
    /// zkEVM challenge API.
    pub challenges: Challenges<Expression<F>>,
}

/// blob circuit config
// #[derive(Clone, Debug)]
pub struct BlobCircuitConfig<F: Field> {
    /// Field config for bls12-381::Scalar.
    fp_config: FpConfig<F, Fp>,
    /// Number of limbs to represent Fp.
    num_limbs: usize,
    /// Number of bits per limb.
    limb_bits: usize,
    _marker: PhantomData<F>,
}

/// BlobCircuit
#[derive(Default, Clone, Debug)]
pub struct BlobCircuit<F> {
    /// commit of batch
    pub batch_commit: F,
    /// challenge point x
    pub challenge_point: F,
    /// index of blob element    
    pub index: usize,
    /// partial blob element    
    pub partial_blob: [Fp; 32],
    _marker: PhantomData<F>,
}


impl<F: Field> SubCircuitConfig<F> for BlobCircuitConfig<F>{
    type ConfigArgs = BlobCircuitConfigArgs<F>;
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            challenges: _,
        }: Self::ConfigArgs,
    ) -> Self {
        let num_limbs = 3;
        let limb_bits = 88;
        #[cfg(feature = "onephase")]
        let num_advice = [35];
        #[cfg(not(feature = "onephase"))]
        let num_advice = [35, 1];

        let fp_config = FpConfig::configure(
            meta,
            FpStrategy::Simple,
            &num_advice,
            &[17], // num lookup advice
            1,     // num fixed
            13,    // lookup bits
            limb_bits,
            num_limbs,
            modulus::<Fp>(),
            0,
            20, // k
        );
        Self {
            fp_config,
            num_limbs,
            limb_bits,
            _marker: PhantomData,
        }
    }
} 

impl<F: Field> BlobCircuit<F>{
    pub(crate) fn assign(
        &self,
        ctx: &mut Context<F>,
        fp_chip: &FpConfig<F, Fp>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {

       
        let gate = &fp_chip.range.gate;

        let one_fp = fp_chip.load_constant(ctx, fe_to_biguint(&Fp::one()));

        let zero = gate.load_zero(ctx);

        let challenge_point = gate.load_witness(ctx, Value::known(self.challenge_point));

        let blob = self
            .partial_blob
            .iter()
            .map(|x| fp_chip.load_private(ctx, Value::known(fe_to_bigint(x))))
            .collect::<Vec<_>>();

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
        let (cp_lo, cp_hi) = decompose_to_lo_hi(ctx, &fp_chip.range, challenge_point);
            
        let challenge_point_fp = cross_field_load_private(ctx, &fp_chip, &fp_chip.range, &cp_lo, &cp_hi);

        // loading roots of unity to fp_chip as constants
        let blob_width_th_root_of_unity =
        Fp::from(123).pow(&[(FP_S - BLOB_WIDTH_BITS) as u64, 0, 0, 0]);
        let roots_of_unity: Vec<_> = (0..BLOB_WIDTH)
            .map(|i| blob_width_th_root_of_unity.pow(&[i as u64, 0, 0, 0]))
            .collect();
        let roots_of_unity = roots_of_unity
            .iter()
            .map(|x| fp_chip.load_constant(ctx, fe_to_biguint(x)))
            .collect::<Vec<_>>();          

        // apply bit_reversal_permutation to roots_of_unity
        // spec reference:
        // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#bit-reversal-permutation
        //
        let roots_of_unity_brp = bit_reversal_permutation(roots_of_unity);

        let mut result = fp_chip.load_constant(ctx, fe_to_biguint(&Fp::zero()));
        let mut cp_is_not_root_of_unity = fp_chip.load_constant(ctx, fe_to_biguint(&Fp::one()));
        let mut barycentric_evaluation = fp_chip.load_constant(ctx, fe_to_biguint(&Fp::zero()));
        
        for i in 0..BLOB_WIDTH as usize {
            let numinator_i = fp_chip.mul(ctx, &roots_of_unity_brp[i].clone(), &blob[i].clone());
    
            let denominator_i_no_carry = fp_chip.sub_no_carry(
                ctx,
                &challenge_point_fp.clone(),
                &roots_of_unity_brp[i].clone(),
            );
            let denominator_i = fp_chip.carry_mod(ctx, &denominator_i_no_carry);
            // avoid division by zero
            // safe_denominator_i = denominator_i       (denominator_i != 0)
            // safe_denominator_i = 1                   (denominator_i == 0)
            let is_zero_denominator_i = fp_is_zero(ctx, &gate, &denominator_i);
            let is_zero_denominator_i =
                cross_field_load_private(ctx, &fp_chip, &fp_chip.range, &is_zero_denominator_i, &zero);
            let safe_denominator_i =
                fp_chip.add_no_carry(ctx, &denominator_i, &is_zero_denominator_i.clone());
            let safe_denominator_i = fp_chip.carry_mod(ctx, &safe_denominator_i);

            // update `cp_is_not_root_of_unity`
            // cp_is_not_root_of_unity = 1          (initialize)
            // cp_is_not_root_of_unity = 0          (denominator_i == 0)
            let non_zero_denominator_i =
                fp_chip.sub_no_carry(ctx, &one_fp.clone(), &is_zero_denominator_i.clone());
            cp_is_not_root_of_unity = fp_chip.mul(ctx, &cp_is_not_root_of_unity, &non_zero_denominator_i);

            // update `result`
            // result = blob[i]     (challenge_point = roots_of_unity_brp[i])
            let select_blob_i = fp_chip.mul(ctx, &blob[i].clone(), &is_zero_denominator_i.clone());
            let tmp_result = fp_chip.add_no_carry(ctx, &result, &select_blob_i);
            result = fp_chip.carry_mod(ctx, &tmp_result);

            let term_i = fp_chip.divide(ctx, &numinator_i, &safe_denominator_i);
            let evaluation_not_proper = fp_chip.add_no_carry(ctx, &barycentric_evaluation, &term_i);
            barycentric_evaluation = fp_chip.carry_mod(ctx, &evaluation_not_proper);
        }
        let cp_to_the_width = fp_pow(ctx, &fp_chip, &challenge_point_fp, BLOB_WIDTH as u32);
        let cp_to_the_width_minus_one = fp_chip.sub_no_carry(ctx, &cp_to_the_width, &one_fp);
        let cp_to_the_width_minus_one = fp_chip.carry_mod(ctx, &cp_to_the_width_minus_one);
        let width_fp = fp_chip.load_constant(ctx, fe_to_biguint(&Fp::from(BLOB_WIDTH as u64)));
        let factor = fp_chip.divide(ctx, &cp_to_the_width_minus_one, &width_fp);
        barycentric_evaluation = fp_chip.mul(ctx, &barycentric_evaluation, &factor);
    
        // === STEP 3: select between the two case ===
        // if challenge_point is a root of unity, then result = blob[i]
        // else result = barycentric_evaluation
        let select_evaluation = fp_chip.mul(ctx, &barycentric_evaluation, &cp_is_not_root_of_unity);
        let tmp_result = fp_chip.add_no_carry(ctx, &result, &select_evaluation);
        result = fp_chip.carry_mod(ctx, &tmp_result);

        //make_public.extend(result.limbs());
        
        Ok(())

    }
}


impl<F: Field> SubCircuit<F> for BlobCircuit<F>{
    type Config = BlobCircuitConfig<F>;


    fn new_from_block(block: &Block<F>) -> Self {
        Self{
            batch_commit: F::random(OsRng), 
            challenge_point: F::random(OsRng),
            index: 0,
            partial_blob: (0..BLOB_WIDTH)
            .map(|_| Fp::random(OsRng))
            .collect::<Vec<Fp>>()
            .try_into()
            .unwrap(),
            _marker: Default::default(),
        }
    }

    fn min_num_rows_block(block: &Block<F>) -> (usize, usize) {
        (100,100)
    }



    fn synthesize_sub(
        &self,
        config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {

        layouter.assign_region(
            || "assign blob circuit", 
            |mut region| {

                let fp_chip = FpConfig::<F, Fp>::construct(
                    config.fp_config.range.clone(),
                    config.limb_bits,
                    config.num_limbs,
                    modulus::<Fp>(),
                );
                let mut ctx = fp_chip.new_context(region);

               self.assign(&mut ctx, &fp_chip, _challenges)
            },
        )?;        
        

        Ok(())
    }
}

