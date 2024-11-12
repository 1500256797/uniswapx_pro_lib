use std::str::FromStr;

use alloy::primitives::Address;

use super::chain::ChainId;

pub struct Weth9(pub Address);

impl From<ChainId> for Weth9 {
    fn from(chain_id: ChainId) -> Self {
        Weth9(Address::from_str(weth_address(chain_id).0).unwrap())
    }
}

impl From<u64> for Weth9 {
    fn from(chain_id: u64) -> Self {
        Weth9::from(ChainId::from(chain_id))
    }
}

pub fn weth_address(chain_id: ChainId) -> (&'static str, u8, &'static str, &'static str) {
    match chain_id.into() {
        1 => (
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        11155111 => (
            "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        3 => (
            "0xc778417E063141139Fce010982780140Aa0cD5Ab",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        4 => (
            "0xc778417E063141139Fce010982780140Aa0cD5Ab",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        5 => (
            "0xB4FBF271143F4FBf7B91A5ded31805e42b2208d6",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        42 => (
            "0xd0A1E359811322d97991E03f863a0C30C2cF029C",
            18,
            "WETH",
            "Wrapped Ether",
        ),

        10 => (
            "0x4200000000000000000000000000000000000006",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        69 => (
            "0x4200000000000000000000000000000000000006",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        11155420 => (
            "0x4200000000000000000000000000000000000006",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        42161 => (
            "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        421611 => (
            "0xB47e6A5f8b33b3F17603C83a0535A9dcD7E32681",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        421614 => (
            "0x980B62Da83eFf3D4576C647993b0c1D7faf17c73",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        8453 => (
            "0x4200000000000000000000000000000000000006",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        56 => (
            "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
            18,
            "WBNB",
            "Wrapped BNB",
        ),
        137 => (
            "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
            18,
            "WMATIC",
            "Wrapped MATIC",
        ),
        43114 => (
            "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7",
            18,
            "WAVAX",
            "Wrapped AVAX",
        ),
        7777777 => (
            "0x4200000000000000000000000000000000000006",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        81457 => (
            "0x4300000000000000000000000000000000000004",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        324 => (
            "0x5AEa5775959fBC2557Cc8789bC1bf90A239D9a91",
            18,
            "WETH",
            "Wrapped Ether",
        ),

        480 => (
            "0x4200000000000000000000000000000000000006",
            18,
            "WETH",
            "Wrapped Ether",
        ),

        1301 => (
            "0x4200000000000000000000000000000000000006",
            18,
            "WETH",
            "Wrapped Ether",
        ),
        _ => panic!("Unknown chain ID for WETH address"),
    }
}
