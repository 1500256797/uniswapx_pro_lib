use std::sync::Arc;

use anyhow::Result;

use crate::prelude::*;
use crate::v3_sdk::uniswapv3_pool::UniswapPoolFee;
use alloy::sol;
use alloy::{
    primitives::{aliases::U24, Address, U160, U256},
    providers::ProviderBuilder,
};
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    UNIV3_QUOTER,
    "src/abi/uniswapv3_quoter.json"
);
const UNIV3_QUOTER_CONTRACT_ADDR: &str = "0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6";
pub struct QuoteExactInputSingleParams {
    pub token_in: Address,
    pub token_out: Address,
    pub fee: UniswapPoolFee,
    pub amount_in: U256,
    pub sqrt_price_limit_x96: U256,
}

pub struct QuoteExactOutputSingleParams {
    pub token_in: Address,
    pub token_out: Address,
    pub fee: UniswapPoolFee,
    pub amount_out: U256,
    pub sqrt_price_limit_x96: U256,
}

pub enum UniswapV3QuoterCommand {
    /// quoteExactInputSingle - given the amount you want to swap, produces a quote for the amount out for a swap of a single pool
    QuoteExactInputSingle(QuoteExactInputSingleParams),
    // quoteExactOutputSingle - given the amount you want to get out, produces a quote for the amount in for a swap over a single pool
    QuoteExactOutputSingle(QuoteExactOutputSingleParams),
}

#[derive(Debug)]
pub enum UniswapV3QuoterResult {
    QuoteExactInputSingle(U256),
    QuoteExactOutputSingle(U256),
}

#[derive(thiserror::Error, Debug)]
pub enum UniswapV3QuoterError {
    #[error("错误的池子费用")]
    WrongPoolFee,
    #[error("无效的命令")]
    InvalidCommand,
    #[error("RPC 无法连接 {0}")]
    InvalidRpcUrl(String),

    #[error("地址格式不正确{0}")]
    InvalidAddress(String),
}

pub async fn execute(
    command: UniswapV3QuoterCommand,
    rpc_url: String,
) -> Result<UniswapV3QuoterResult, UniswapV3QuoterError> {
    let provider = ProviderBuilder::new()
        .on_builtin(&rpc_url)
        .await
        .map_err(|e| UniswapV3QuoterError::InvalidRpcUrl(e.to_string()))?;

    let client = Arc::new(provider);
    let quoter_address = Address::from_str(UNIV3_QUOTER_CONTRACT_ADDR)
        .map_err(|e| UniswapV3QuoterError::InvalidAddress(e.to_string()))?;
    let contract = UNIV3_QUOTER::new(quoter_address, client);
    match command {
        UniswapV3QuoterCommand::QuoteExactInputSingle(params) => {
            let call_res = contract
                .quoteExactInputSingle(
                    params.token_in,
                    params.token_out,
                    U24::from(params.fee.as_u32()),
                    params.amount_in,
                    U160::from(params.sqrt_price_limit_x96),
                )
                .call()
                .await
                .map_err(|e| UniswapV3QuoterError::WrongPoolFee)?;
            Ok(UniswapV3QuoterResult::QuoteExactInputSingle(
                call_res.amountOut,
            ))
        }
        UniswapV3QuoterCommand::QuoteExactOutputSingle(params) => {
            let call_res = contract
                .quoteExactOutputSingle(
                    params.token_in,
                    params.token_out,
                    U24::from(params.fee.as_u32()),
                    params.amount_out,
                    U160::from(params.sqrt_price_limit_x96),
                )
                .call()
                .await
                .map_err(|e| UniswapV3QuoterError::WrongPoolFee)?;
            Ok(UniswapV3QuoterResult::QuoteExactOutputSingle(
                call_res.amountIn,
            ))
        }
        _ => Err(UniswapV3QuoterError::InvalidCommand),
    }
}

#[cfg(test)]
mod tests {

    use crate::core_sdk::currency::{Erc20Token, Erc20TokenBuilder};
    use crate::v3_sdk::uniswapv3_pool::UniswapPoolFee;

    use super::*;
    #[tokio::test]
    async fn test_get_token_price() {
        let weth: Address =
            Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let token_out: Address =
            Address::from_str("0x535887989b9EdffB63b1Fd5C6b99a4d45443b49a").unwrap();
        let amount_in = Erc20Token::from_readable_amount(dec!(1.0), 18);
        let sqrt_price_limit_x96 = 0;
        let quote_exact_input_params = QuoteExactInputSingleParams {
            token_in: weth,
            token_out,
            fee: UniswapPoolFee::Fee10000,
            amount_in: amount_in.into(),
            sqrt_price_limit_x96: U256::from(sqrt_price_limit_x96),
        };
        let command = UniswapV3QuoterCommand::QuoteExactInputSingle(quote_exact_input_params);
        let res = execute(command, "https://eth.llamarpc.com".to_string())
            .await
            .unwrap();

        if let UniswapV3QuoterResult::QuoteExactInputSingle(res) = res {
            let amount_out = Erc20Token::to_readable_amount(res, 9);
            println!("amount_out: {}", amount_out);
        }
    }

    #[tokio::test]
    async fn test_get_token_price_turbo() {
        let weth: Address =
            Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let turbo: Address =
            Address::from_str("0xA35923162C49cF95e6BF26623385eb431ad920D3").unwrap();
        let amount_in = Erc20Token::from_readable_amount(dec!(1.0), 18);
        let sqrt_price_limit_x96 = 0;
        let quote_exact_input_params = QuoteExactInputSingleParams {
            token_in: weth,
            token_out: turbo,
            fee: UniswapPoolFee::Fee10000,
            amount_in: amount_in.into(),
            sqrt_price_limit_x96: U256::from(sqrt_price_limit_x96),
        };
        let command = UniswapV3QuoterCommand::QuoteExactInputSingle(quote_exact_input_params);
        let res = execute(command, "https://eth.llamarpc.com".to_string())
            .await
            .unwrap();

        if let UniswapV3QuoterResult::QuoteExactInputSingle(res) = res {
            let amount_out = Erc20Token::to_readable_amount(res, 18);
            println!("amount_out: {}", amount_out);
            assert!(amount_out > 0.0);
        }
    }

    #[tokio::test]
    async fn test_exact_output_single() {
        let weth: Address =
            Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let meme: Address =
            Address::from_str("0x535887989b9EdffB63b1Fd5C6b99a4d45443b49a").unwrap();
        let amount_out = Erc20Token::from_readable_amount(dec!(100000.0), 9);
        let sqrt_price_limit_x96 = 0;
        let quote_exact_out_params = QuoteExactOutputSingleParams {
            token_in: weth,
            token_out: meme,
            fee: UniswapPoolFee::Fee10000,
            amount_out: amount_out.into(),
            sqrt_price_limit_x96: U256::from(sqrt_price_limit_x96),
        };
        let command = UniswapV3QuoterCommand::QuoteExactOutputSingle(quote_exact_out_params);
        let res = execute(command, "https://eth.llamarpc.com".to_string())
            .await
            .unwrap();

        if let UniswapV3QuoterResult::QuoteExactOutputSingle(res) = res {
            let amount_in = Erc20Token::to_readable_amount(res, 18);
            println!("amount_in: {}", amount_in);
        }
    }

    #[tokio::test]
    async fn test_exact_output_single_turbo() {
        let weth: Address =
            Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let meme: Address =
            Address::from_str("0xA35923162C49cF95e6BF26623385eb431ad920D3").unwrap();
        let amount_out = Erc20Token::from_readable_amount(dec!(1000.0), 18);
        let sqrt_price_limit_x96 = 0;
        let quote_exact_out_params = QuoteExactOutputSingleParams {
            token_in: weth,
            token_out: meme,
            fee: UniswapPoolFee::Fee10000,
            amount_out: amount_out.into(),
            sqrt_price_limit_x96: U256::from(sqrt_price_limit_x96),
        };
        let command = UniswapV3QuoterCommand::QuoteExactOutputSingle(quote_exact_out_params);
        let res = execute(command, "https://eth.llamarpc.com".to_string())
            .await
            .unwrap();

        if let UniswapV3QuoterResult::QuoteExactOutputSingle(res) = res {
            let amount_in = Erc20Token::to_readable_amount(res, 18);
            println!("amount_in: {}", amount_in);
        }
    }

    #[tokio::test]
    async fn test_get_token_price_with_wrong_fee() {
        let weth: Address =
            Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let token_out: Address =
            Address::from_str("0x535887989b9EdffB63b1Fd5C6b99a4d45443b49a").unwrap();
        let amount_in = Erc20Token::from_readable_amount(dec!(1.0), 18);
        let sqrt_price_limit_x96 = 0;
        let quote_exact_input_params = QuoteExactInputSingleParams {
            token_in: weth,
            token_out,
            fee: UniswapPoolFee::Fee100,
            amount_in: amount_in.into(),
            sqrt_price_limit_x96: U256::from(sqrt_price_limit_x96),
        };
        let command = UniswapV3QuoterCommand::QuoteExactInputSingle(quote_exact_input_params);
        let res = execute(command, "https://eth.llamarpc.com".to_string())
            .await
            .unwrap_err();

        assert_eq!(
            res.to_string(),
            UniswapV3QuoterError::WrongPoolFee.to_string()
        );
    }
}
