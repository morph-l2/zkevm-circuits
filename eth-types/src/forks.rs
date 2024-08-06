//! Hardfork related codes for Scroll networks
use crate::constants::read_env_var;

/// Hardfork ID for scroll networks
#[derive(Debug, PartialEq, Eq)]
pub enum HardforkId {
    /// Curie hardfork
    Curie = 3,
}

/// Morph devnet and qanet chain id
pub const MORPH_DEVNET_CHAIN_ID: u64 = 53077;
/// Morph testnet chain id
pub const MORPH_TESTNET_CHAIN_ID: u64 = 2810;
/// Morph mainnet chain id
pub const MORPH_MAINNET_CHAIN_ID: u64 = 2818;

/// Get hardforks of Morph networks.
/// Returns a list of triplets of (hardfork id, chain id, block number)
pub fn hardfork_heights() -> Vec<(HardforkId, u64, u64)> {
    vec![
        (
            HardforkId::Curie,
            MORPH_DEVNET_CHAIN_ID,
            read_env_var("MORPH_DEVNET_CURIE_BLOCK", u64::MAX),
        ), // devnet and qanet
        (
            HardforkId::Curie,
            MORPH_TESTNET_CHAIN_ID,
            read_env_var("MORPH_TESTNET_CURIE_BLOCK", u64::MAX),
        ), // testnet
        (
            HardforkId::Curie,
            MORPH_MAINNET_CHAIN_ID,
            read_env_var("MORPH_MAINNET_CURIE_BLOCK", u64::MAX),
        ), // mainnet
    ]
}
