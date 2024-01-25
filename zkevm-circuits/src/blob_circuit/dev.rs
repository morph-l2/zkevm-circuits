use super::*;

//#[cfg(not(feature = "onephase"))]
use crate::util::Challenges;
//#[cfg(feature = "onephase")]
//use crate::util::MockChallenges as Challenges;


use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::{Circuit, Challenge}};


impl<F: Field> Circuit<F> for BlobCircuit<F> {
    type Config = (BlobCircuitConfig<F>, Challenges<Challenge>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            BlobCircuitConfig::new(
                meta,
                BlobCircuitConfigArgs {
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = config.1.values(&layouter);
        
        self.synthesize_sub(&config.0, &challenges, &mut layouter)
    }
}