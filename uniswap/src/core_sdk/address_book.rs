use std::str::FromStr;

use alloy::primitives::Address;

use super::chain::ChainId;

pub struct UniversalRouterAddress(pub Address);

impl From<ChainId> for UniversalRouterAddress {
    fn from(chain_id: ChainId) -> Self {
        match chain_id {
            ChainId::Mainnet => UniversalRouterAddress(
                Address::from_str("0x7a250d5630b4cf539739df2c5dacab8e80291cfc").unwrap(),
            ),
            ChainId::Bnb => UniversalRouterAddress(
                Address::from_str("0x4Dae2f939ACf50408e13d58534Ff8c2776d45265").unwrap(),
            ),
            _ => panic!(
                "Can't find universal router address for chain id: {:?}",
                chain_id
            ),
        }
    }
}
