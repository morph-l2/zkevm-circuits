use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_WORD_SIZE, N_BYTES_U64},
        step::ExecutionState,
        util::{
            common_gadget::{SameContextGadget, WordByteCapGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryCopierGasGadget,
                MemoryExpansionGadget,
            },
            not, select, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{Expr, Field},
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::evm_types::GasCost;
use gadgets::ToScalar;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct CallDataCopyGadget<F> {
    same_context: SameContextGadget<F>,
    memory_address: MemoryAddressGadget<F>,
    data_offset: WordByteCapGadget<F, N_BYTES_U64>,
    src_id: Cell<F>,
    call_data_length: Cell<F>,
    call_data_offset: Cell<F>, // Only used in the internal call
    copy_rwc_inc: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
}

impl<F: Field> ExecutionGadget<F> for CallDataCopyGadget<F> {
    const NAME: &'static str = "CALLDATACOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATACOPY;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let src_id = cb.query_cell();
        let call_data_length = cb.query_cell();
        let call_data_offset = cb.query_cell();

        let length = cb.query_word_rlc();
        let memory_offset = cb.query_cell_phase2();
        let data_offset = WordByteCapGadget::construct(cb, call_data_length.expr());

        // Pop memory_offset, data_offset, length from stack
        cb.stack_pop(memory_offset.expr());
        cb.stack_pop(data_offset.original_word());
        cb.stack_pop(length.expr());

        // Lookup the calldata_length and caller_address in Tx context table or
        // Call context table
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            cb.call_context_lookup(false.expr(), None, CallContextFieldTag::TxId, src_id.expr());
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallDataLength,
                call_data_length.expr(),
            );
            cb.require_zero(
                "call_data_offset == 0 in the root call",
                call_data_offset.expr(),
            );
        });
        cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallerId,
                src_id.expr(),
            );
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallDataLength,
                call_data_length.expr(),
            );
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallDataOffset,
                call_data_offset.expr(),
            );
        });

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_address = MemoryAddressGadget::construct(cb, memory_offset, length);
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.end_offset()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        let copy_rwc_inc = cb.query_cell();
        let src_tag = select::expr(
            cb.curr.state.is_root.expr(),
            CopyDataType::TxCalldata.expr(),
            CopyDataType::Memory.expr(),
        );
        cb.condition(memory_address.has_length(), |cb| {
            // Set source start to the minimun value of data offset and call data length.
            let src_addr = call_data_offset.expr()
                + select::expr(
                    data_offset.lt_cap(),
                    data_offset.valid_value(),
                    call_data_length.expr(),
                );

            let src_addr_end = call_data_offset.expr() + call_data_length.expr();

            cb.copy_table_lookup(
                src_id.expr(),
                src_tag,
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                src_addr,
                src_addr_end,
                memory_address.offset(),
                memory_address.length(),
                0.expr(), // for CALLDATACOPY rlc_acc is 0
                copy_rwc_inc.expr(),
            );
        });
        cb.condition(not::expr(memory_address.has_length()), |cb| {
            cb.require_zero(
                "if no bytes to copy, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

        // State transition
        let step_state_transition = StepStateTransition {
            // 1 tx id lookup + 3 stack pop + option(calldatalength lookup)
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(3.expr()),
            gas_left: Delta(
                -(OpcodeId::CALLDATACOPY.constant_gas_cost().expr() + memory_copier_gas.gas_cost()),
            ),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            data_offset,
            src_id,
            call_data_length,
            call_data_offset,
            copy_rwc_inc,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [memory_offset, data_offset, length] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
                .map(|idx| block.rws[idx].stack_value());
        let memory_address = self
            .memory_address
            .assign(region, offset, memory_offset, length)?;
        let src_id = if call.is_root { tx.id } else { call.caller_id };
        self.src_id.assign(
            region,
            offset,
            Value::known(F::from(u64::try_from(src_id).unwrap())),
        )?;

        // Call data length and call data offset
        let (call_data_length, call_data_offset) = if call.is_root {
            (
                if tx.is_create {
                    0
                } else {
                    tx.call_data_length as u64
                },
                0_u64,
            )
        } else {
            (call.call_data_length, call.call_data_offset)
        };
        self.call_data_length
            .assign(region, offset, Value::known(F::from(call_data_length)))?;
        self.call_data_offset
            .assign(region, offset, Value::known(F::from(call_data_offset)))?;

        self.data_offset
            .assign(region, offset, data_offset, F::from(call_data_length))?;

        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                step.copy_rw_counter_delta
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        // Memory expansion
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;

        self.memory_copier_gas.assign(
            region,
            offset,
            length.as_u64(),
            memory_expansion_gas_cost,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{bytecode, word, Bytecode, Word};
    use mock::{
        eth, generate_mock_call_bytecode,
        test_ctx::{helpers::*, TestContext},
        MockCallBytecodeParams, MOCK_ACCOUNTS,
    };

    fn test_root_ok(
        call_data_length: usize,
        length: usize,
        data_offset: Word,
        memory_offset: Word,
    ) {
        let bytecode = bytecode! {
            PUSH32(length)
            PUSH32(data_offset)
            PUSH32(memory_offset)
            #[start]
            CALLDATACOPY
            STOP
        };
        let call_data = rand_bytes(call_data_length);

        // Get the execution steps from the external tracer
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(bytecode),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .input(call_data.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_calldata: 600,
                ..CircuitsParams::default()
            })
            .run();
    }

    fn test_internal_ok(
        call_data_offset: usize,
        call_data_length: usize,
        length: usize,
        data_offset: Word,
        dst_offset: Word,
    ) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = bytecode! {
            .op_calldatacopy(dst_offset, data_offset, length)
            STOP
        };

        let code_a = generate_mock_call_bytecode(MockCallBytecodeParams {
            address: addr_b,
            pushdata: rand_bytes(32),
            call_data_length,
            call_data_offset,
            ..MockCallBytecodeParams::default()
        });

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn calldatacopy_gadget_simple() {
        test_root_ok(0x40, 10, 0x00.into(), 0x40.into());
        test_internal_ok(0x40, 0x40, 10, 0x10.into(), 0x00.into());
        test_internal_ok(0x40, 0x40, 10, 0x10.into(), 0xA0.into());
    }

    #[test]
    fn calldatacopy_gadget_large() {
        test_root_ok(0x204, 0x1, 0x102.into(), 0x101.into());
        test_root_ok(0x204, 0x101, 0x102.into(), 0x103.into());
        test_internal_ok(0x30, 0x204, 0x101, 0x102.into(), 0x103.into());
    }

    #[test]
    fn calldatacopy_gadget_out_of_bound() {
        test_root_ok(0x40, 40, 0x20.into(), 0x40.into());
        test_internal_ok(0x40, 0x20, 10, 0x28.into(), 0xA0.into());
    }

    #[test]
    fn calldatacopy_gadget_zero_length() {
        test_root_ok(0x40, 0, 0x00.into(), 0x40.into());
        test_internal_ok(0x40, 0x40, 0, 0x10.into(), 0xA0.into());
    }

    #[test]
    fn calldatacopy_gadget_data_offset_overflow() {
        test_root_ok(0x40, 10, Word::MAX, 0x40.into());
        test_internal_ok(0x40, 0x40, 10, Word::MAX, 0xA0.into());
    }

    #[test]
    fn calldatacopy_gadget_overflow_memory_offset_and_zero_length() {
        test_root_ok(0x40, 0, 0x40.into(), Word::MAX);
        test_internal_ok(0x40, 0x40, 0, 0x10.into(), Word::MAX);
    }

    #[test]
    fn calldatacopy_unaligned_data() {
        // calldatacopy_d0(cdc_0_1_2)_g0_v0
        test_internal_ok(0xf, 0x10, 2, 1.into(), 0x0.into());

        // copy source out of bounds
        test_internal_ok(0xf, 0x10, 0x9, 0x20.into(), 0x0.into());

        // calldatacopy_d4(cdc_0_neg6_ff)_g0_v0
        test_internal_ok(
            0xf,
            0x10,
            0x09,
            word!("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa"),
            0x0.into(),
        );
    }

    fn initialization_bytecode(length: usize, data_offset: Word, dst_offset: Word) -> Bytecode {
        let memory_bytes = [0x60; 10];
        let memory_value = Word::from_big_endian(&memory_bytes);

        let code = bytecode! {
            PUSH32(length)
            PUSH32(data_offset)
            PUSH32(dst_offset)
            CALLDATACOPY
            PUSH10(memory_value)
            PUSH32(0)
            MSTORE
            PUSH2( 5 ) // length to copy
            PUSH2(u64::try_from(memory_bytes.len()).unwrap()) // offset
            RETURN
        };

        code
    }

    // tx deploy case.
    #[test]
    fn test_tx_deploy_calldatacopy() {
        let code = initialization_bytecode(10, Word::from(10), Word::from(0x30));

        let ctx = TestContext::<1, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
            },
            |mut txs, _accs| {
                txs[0]
                    .from(MOCK_ACCOUNTS[0])
                    .gas(58000u64.into())
                    .value(eth(2))
                    .input(code.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
