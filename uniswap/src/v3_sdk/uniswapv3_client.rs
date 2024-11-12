use alloy::{
    network::TransactionBuilder,
    primitives::{Address, U160, U256},
    providers::ProviderBuilder,
};
// send a swap transaction
use crate::prelude::*;
use crate::{
    v3_sdk::uniswapv3_pool::UniswapPoolFee,
    v3_sdk::uniswapv3_router,
    v3_sdk::uniswapv3_router::{ExactInputSingleParams, UniswapV3RouterCommand},
};
use anyhow::{Ok, Result};
pub enum UniswapSupportChain {
    Ethereum,
    Base,
}

impl UniswapSupportChain {
    pub fn get_rpc_url(&self) -> String {
        match self {
            UniswapSupportChain::Ethereum => "https://mainnet.base.org".to_string(),
            UniswapSupportChain::Base => "https://mainnet.base.org".to_string(),
        }
    }

    pub fn as_chain_id(&self) -> u64 {
        match self {
            UniswapSupportChain::Ethereum => 1,
            UniswapSupportChain::Base => 8453,
        }
    }
}

pub enum SwapDirection {
    ExactInput,
    ExactOutput,
}

pub enum UniswapVersion {
    V2,
    V3,
}

pub struct SwapParams {
    pub token_in: Address,
    pub token_out: Address,
    pub amount_in: U256,
    pub amount_out_min: U256,
    pub pool_fee: UniswapPoolFee,
    pub recipient: Address,
    pub deadline: U256,
}

pub async fn swap(
    chain: UniswapSupportChain,
    direction: SwapDirection,
    uniswap_version: UniswapVersion,
    params: SwapParams,
    rpc_url: String,
) -> Result<()> {
    match uniswap_version {
        UniswapVersion::V2 => {
            // V2 逻辑
            Ok(())
        }
        UniswapVersion::V3 => {
            // 判断是 ExactInput 还是 ExactOutput
            match direction {
                SwapDirection::ExactInput => {
                    let params = ExactInputSingleParams {
                        token_in: params.token_in,
                        token_out: params.token_out,
                        fee: params.pool_fee,
                        recipient: params.recipient,
                        deadline: params.deadline,
                        amount_in: params.amount_in,
                        amount_out_minimum: params.amount_out_min,
                        sqrt_price_limit_x96: U256::from(0),
                    };
                    let tx = uniswapv3_router::execute(
                        UniswapV3RouterCommand::ExactInputSingle(params),
                        rpc_url,
                    )
                    .await?;
                    let tx = tx.with_chain_id(chain.as_chain_id());
                    println!("tx: {:?}", tx);
                    Ok(())
                }
                SwapDirection::ExactOutput => Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use crate::core_sdk::currency::{Erc20Token, Erc20TokenBuilder};

    use super::*;
    use alloy::{
        network::{EthereumWallet, TransactionBuilder},
        primitives::{address, U256},
        providers::{Provider, ProviderBuilder},
        rpc::types::TransactionRequest,
        signers::ledger::{HDPath, LedgerSigner},
    };

    #[tokio::test]
    async fn test_swap() {
        let mainet_rpc = "https://eth.llamarpc.com";
        // Create a provider with the wallet.
        // https://github.com/alloy-rs/examples/blob/65126561b942e642bd6c34d4df7676f39779b283/examples/wallets/Cargo.toml
        let weth = Erc20TokenBuilder::default()
            .address(Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap())
            .decimals(18)
            .symbol(Some("WETH".to_string()))
            .name(Some("Wrapped Ether".to_string()))
            .build()
            .unwrap()
            .update_token_info(mainet_rpc)
            .await
            .unwrap();
        let ethc = Erc20TokenBuilder::default()
            .address(Address::from_str("0x35c8941c294E9d60E0742CB9f3d58c0D1Ba2DEc4").unwrap())
            .build()
            .unwrap()
            .update_token_info(mainet_rpc)
            .await
            .unwrap();
        let receiver: Address = "0xCa017e24f449Ec454E94C843bbbF2cE61b7F6B69"
            .parse()
            .unwrap();
        let params = SwapParams {
            token_in: weth.address,
            token_out: ethc.address,
            amount_in: Erc20Token::from_readable_amount(dec!(0.01), weth.decimals),
            amount_out_min: U256::ZERO,
            pool_fee: UniswapPoolFee::Fee10000,
            recipient: receiver,
            deadline: U256::ZERO,
        };
        let tx = swap(
            UniswapSupportChain::Ethereum,
            SwapDirection::ExactInput,
            UniswapVersion::V3,
            params,
            mainet_rpc.to_string(),
        )
        .await
        .unwrap();
    }
}
