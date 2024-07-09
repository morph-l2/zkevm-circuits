use super::{CachedRegion, Cell};
use crate::{
    evm_circuit::{
        table::{FixedTableTag, Lookup},
        util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{IsZeroGadget, LtGadget},
        },
    },
    table::BlockContextFieldTag,
    util::{Expr, Field},
};

use eth_types::forks::{
    HardforkId, MORPH_DEVNET_CHAIN_ID, MORPH_MAINNET_CHAIN_ID, MORPH_TESTNET_CHAIN_ID,
};
use gadgets::util::not;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct CurieGadget<F> {
    chain_id: Cell<F>,
    /// Morph chains have non-zero curie hard fork block number
    is_morph_chain: IsZeroGadget<F>,
    /// The block height at which curie hard fork happens
    curie_fork_block_num: Cell<F>,
    pub(crate) is_before_curie: LtGadget<F, 8>, // block num is u64
}

impl<F: Field> CurieGadget<F> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, block_number: Expression<F>) -> Self {
        let chain_id = cb.query_cell();
        // Lookup block table with chain_id
        cb.block_lookup(
            BlockContextFieldTag::ChainId.expr(),
            block_number.expr(),
            chain_id.expr(),
        );

        // TODO: refactor
        // is_morph_chain means (chain_id - 2818) * (chain_id - 2710) * (chain_id - 53077) == 0
        let is_morph_chain = IsZeroGadget::construct(
            cb,
            (chain_id.expr() - MORPH_MAINNET_CHAIN_ID.expr())
                * (chain_id.expr() - MORPH_DEVNET_CHAIN_ID.expr()),
        );
        // let is_morph_chain = BatchedIsZeroGadget::construct(
        //     cb,
        //     [
        //         chain_id.expr() - MORPH_MAINNET_CHAIN_ID.expr(),
        //         chain_id.expr() - MORPH_TESTNET_CHAIN_ID.expr(),
        //         chain_id.expr() - MORPH_DEVNET_CHAIN_ID.expr(),
        //     ],
        // );

        // For Morph Networks (mainnet, testnet, devnet),
        // curie_fork_block_num should be pre-defined.
        // For other chain ids, it should be 0.
        let curie_fork_block_num = cb.query_cell();
        cb.condition(is_morph_chain.expr(), |cb| {
            cb.add_lookup(
                "Hardfork lookup",
                Lookup::Fixed {
                    tag: FixedTableTag::ChainFork.expr(),
                    values: [
                        (HardforkId::Curie as u64).expr(),
                        chain_id.expr(),
                        curie_fork_block_num.expr(),
                    ],
                },
            );
        });
        cb.condition(not::expr(is_morph_chain.expr()), |cb| {
            cb.require_zero("enable curie since genesis", curie_fork_block_num.expr());
        });

        let is_before_curie = LtGadget::construct(
            cb,
            cb.curr.state.block_number.expr(),
            curie_fork_block_num.expr(),
        );
        Self {
            chain_id,
            is_morph_chain,
            curie_fork_block_num,
            is_before_curie,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        chain_id: u64,
        block_number: u64,
    ) -> Result<(), Error> {
        self.chain_id
            .assign(region, offset, Value::known(F::from(chain_id)))?;
        self.is_morph_chain.assign(
            region,
            offset,
            [
                F::from(chain_id) - F::from(MORPH_MAINNET_CHAIN_ID),
                F::from(chain_id) - F::from(MORPH_DEVNET_CHAIN_ID),
            ],
        )?;
        let curie_fork_block_num = if chain_id == MORPH_TESTNET_CHAIN_ID {
            0
        } else {
            bus_mapping::circuit_input_builder::curie::get_curie_fork_block(chain_id)
        };
        self.curie_fork_block_num.assign(
            region,
            offset,
            Value::known(F::from(curie_fork_block_num)),
        )?;
        self.is_before_curie.assign(
            region,
            offset,
            F::from(block_number),
            F::from(curie_fork_block_num),
        )?;
        Ok(())
    }
}
