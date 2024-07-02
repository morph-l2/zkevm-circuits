# Circuits for zkEVM

This is the zkEVM circuits used in Morph Mainnet. It was forked from Scroll zkevm-circuits and a lot of new features were added later and in the future:

1. Sequencer set circuit for decentralized sequencer
2. EIP4844 circuit
3. Faster hash function circuits for zktrie
4. Faster zero-knowledge proof system

## Docs
 
Detailed circuit docs: <https://github.com/morph-l2/zkevm-circuits/tree/develop/docs>

## Getting started

We recommend developers to go to our [circuit playground repo](https://github.com/morph-l2/morph/tree/main/prover) for a detailed step-by-step guide on how to run proving.

## Project Layout

This repository contains several Rust packages that implement the zkevm. The high-level structure of the repository is as follows:

[`bus-mapping`](https://github.com/morph-l2/zkevm-circuits/tree/develop/bus-mapping)

- a crate designed to parse EVM execution traces and manipulate all of the data they provide in order to obtain structured witness inputs for circuits.

[`circuit-benchmarks`](https://github.com/morph-l2/zkevm-circuits/tree/develop/circuit-benchmarks)

- (Deprecated) Measures performance of each circuit based on proving and verifying time and execution trace parsing and generation for each subcircuit

[`eth-types`](https://github.com/morph-l2/zkevm-circuits/tree/develop/eth-types)

- Different types helpful for various components of the EVM

[`external-tracer`](https://github.com/morph-l2/zkevm-circuits/tree/develop/external-tracer)

- Generates traces by connecting to an locally linked Geth EVM tracer

[`gadgets`](https://github.com/morph-l2/zkevm-circuits/tree/develop/gadgets)

- Custom circuits that abstracts away low-level circuit detail.
- [What are gadgets?](https://zcash.github.io/halo2/concepts/gadgets.html)

[`geth-utils`](https://github.com/morph-l2/zkevm-circuits/tree/develop/geth-utils)

- Provides output from geth tracing APIs as circuit inputs

[`integration-tests`](https://github.com/morph-l2/zkevm-circuits/tree/develop/integration-tests)

- Integration tests for all circuits

[`keccak256`](https://github.com/morph-l2/zkevm-circuits/tree/develop/keccak256)

- (Deprecated) Modules for Keccak hash circuit

[`mock`](https://github.com/morph-l2/zkevm-circuits/tree/develop/mock)

- Testing module. Mock definitions and methods that are used to test circuits or opcodes

[`testool`](https://github.com/morph-l2/zkevm-circuits/tree/develop/testool)

- Parser and driver of official Ethereum Execution Tests

[`zkevm-circuits`](https://github.com/morph-l2/zkevm-circuits/tree/develop/zkevm-circuits/src)

- Main package that contains all circuit logic

[`zktrie`](https://github.com/morph-l2/zkevm-circuits/tree/develop/zktrie)

- Wrapper of scroll binary poseidon trie
