use halo2_base::{
    Context,
    utils::{
        ScalarField, bigint_to_fe, biguint_to_fe, bit_length, decompose_bigint_option, decompose_biguint,
        fe_to_biguint, modulus,}, 
    gates::range::{self, RangeConfig}
};

use halo2_ecc::fields::{fp::{FpConfig, FpStrategy}, FieldChip};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Circuit, Expression},
};

use bls12_381::Scalar as Fp;
use crate::util::{SubCircuit, Challenges, SubCircuitConfig};
use std::{marker::PhantomData, ops::Add};
use eth_types::{Field, ToScalar, U256};

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
    pub challenge_point: Fp,
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
        layouter: &mut impl Layouter<F>,
        config: &<Self as SubCircuit<F>>::Config,
        ctx: &mut Context<F>,
        fp_chip: &FpConfig<F, Fp>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {

       
        let gate = fp_chip.range.gate;

        let one_fp = fp_chip.load_constant(ctx, fe_to_biguint(&Fp::one()));

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
            let numinator_i = fp_chip.mul(ctx, roots_of_unity_brp[i].clone(), blob[i].clone());
    
            let denominator_i_no_carry = fp_chip.sub_no_carry(
                ctx,
                challenge_point_fp.clone(),
                roots_of_unity_brp[i].clone(),
            );
        }

        let denominator_i = fp_chip.carry_mod(ctx, denominator_i_no_carry);

        Ok(())

    }
}


impl<F: Field> SubCircuit<F> for BlobCircuit<F>{
    type Config = BlobCircuitConfig<F>;


    fn new_from_block(block: &Block<F>) -> Self {
        self{
            batch_commit: F::random(OsRng), 

            blob: (0..BLOB_WIDTH)
            .map(|_| Fp::random(OsRng))
            .collect::<Vec<Fp>>()
            .try_into()
            .unwrap()
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

        let fp_chip = FpConfig::<F, Fp>::construct(
            config.fp_config.range.clone(),
            config.limb_bits,
            config.num_limbs,
            modulus::<Fp>(),
        );

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

               self.assign(layouter, config, &mut ctx, &fp_chip, _challenges);
                
                Ok(())
            },
        )?;        
        

        Ok(())
    }
}

