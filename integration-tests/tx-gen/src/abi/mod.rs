//! ABIs
//!
//! Contract ABIs are refactored into their own module to gracefully deal with allowing missing docs on the abigen macro.
#![allow(missing_docs)]


pub mod token_abi {
    use ethers::prelude::abigen;
    abigen!(Token, "src/abi/Token.json");
}

