use bls12_381::Scalar as Fp;
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Instance, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

use crate::blob_circuit::to_bytes;

/* Gate design:
    | a0      | a1         | a3(out)| ins    | s_first  | s_other  |
    |---------|------------|--------|--------|----------|----------|
    |data[0]  |data[1..32] |out[0]  |blob[0] | 1        | 0        |
    |data[32] |data[33..64]|out[1]  |blob[1] | 0        | 1        |
    |data[64] |data[65..96]|out[2]  |blob[2] | 0        | 1        |
    ...
    max raw num: 4096
*/

/// Config for the Data bytes to Blob circuit.
#[derive(Clone, Debug)]
pub struct BytesToBlobCircuitConfig<F: Field> {
    /// data input
    advice: [Column<Advice>; 3],
    /// blob
    instance: Column<Instance>,
    s_fir: Selector,
    s_oth: Selector,

    _marker: PhantomData<F>,
}

impl<F: Field> BytesToBlobCircuitConfig<F> {
    fn load_data0(
        &self,
        layouter: &mut impl Layouter<F>,
        value: Value<F>,
        index: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "load data0",
            |mut region| region.assign_advice(|| "advice 0", self.advice[0], index, || value),
        )
    }

    fn load_data1(
        &self,
        layouter: &mut impl Layouter<F>,
        value: Value<F>,
        index: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "load data1",
            |mut region| region.assign_advice(|| "advice 1", self.advice[1], index, || value),
        )
    }

    // fn encode_to_first_blob(
    //     &self,
    //     layouter: &mut impl Layouter<F>,
    //     a: AssignedCell<F, F>,
    //     len: u32,
    // ) -> Result<AssignedCell<F, F>, Error> {
    //     layouter.assign_region(
    //         || "encode 1st blob",
    //         |mut region| {
    //             self.s_fir.enable(&mut region, 0)?;
    //             a.copy_advice(|| "blob first", &mut region, self.advice[1], 0)?;

    //             let value = a.value().copied().map(|x| {
    //                 let mut res = [0; 32];
    //                 res[1..5].copy_from_slice(&len.to_le_bytes());
    //                 res[5..].copy_from_slice(&to_bytes(x)[0..27]);

    //                 Fp::from_bytes(&res).unwrap()
    //             });

    //             region.assign_advice(|| "out", self.advice[2], 0, || value)
    //         },
    //     )
    // }

    fn encode_to_blob(
        &self,
        layouter: &mut impl Layouter<F>,
        a: AssignedCell<F, F>,
        index: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "encode",
            |mut region| {
                self.s_oth.enable(&mut region, index)?;
                a.copy_advice(|| "blob other", &mut region, self.advice[1], index)?;

                let value = a.value().copied();
                region.assign_advice(|| "out", self.advice[2], index, || value)
            },
        )
    }
}

pub struct BytesToBlobCircuit<F: Field> {
    pub data0: Vec<F>,
    pub data1: Vec<F>,
    pub blob: Vec<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for BytesToBlobCircuit<F> {
    type Config = BytesToBlobCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            data0: vec![],
            data1: vec![],
            blob: vec![],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();

        for c in &advice {
            meta.enable_equality(*c);
        }
        meta.enable_equality(instance);
        let s_fir = meta.selector();
        let s_oth = meta.selector();

        // meta.create_gate("encode 0 blob", |meta| {
        //     let _data0 = meta.query_advice(advice[0], Rotation::cur());
        //     let data1 = meta.query_advice(advice[1], Rotation::cur());
        //     let out = meta.query_advice(advice[2], Rotation::cur());
        //     let s = meta.query_selector(s);
        //     Constraints::with_selector(s, vec![data1 - out])
        // });

        meta.create_gate("encode 1 blob", |meta| {
            let _data0 = meta.query_advice(advice[0], Rotation::cur());
            let data1 = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let s = meta.query_selector(s_oth);
            Constraints::with_selector(s, vec![data1 - out])
        });

        BytesToBlobCircuitConfig {
            advice,
            instance,
            s_fir,
            s_oth,
            _marker: PhantomData,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let blob_amount = self.blob.len();
        for i in 0..blob_amount {
            let _data0 = config.load_data0(
                &mut layouter.namespace(|| "load data0"),
                Value::known(self.data0[i]),
                i,
            )?;
            let data1 = config.load_data1(
                &mut layouter.namespace(|| "load data1"),
                Value::known(self.data1[i]),
                i,
            )?;
            let out = config.encode_to_blob(&mut layouter, data1, i)?;

            layouter.namespace(|| "expose out").constrain_instance(
                out.cell(),
                config.instance,
                i,
            )?;
        }
        Ok(())
    }
}
