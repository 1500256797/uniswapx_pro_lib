use super::universal_router_call_data_generator::{
    CurrencyAmount, FeeOptions, Route, RouterTrade, Swap, SwapOptionsBuilder, TradeType,
    UniswapUniversalTrade,
};
use crate::prelude::*;
use crate::{
    core_sdk::{
        address_book::UniversalRouterAddress,
        chain::ChainId,
        currency::{
            Currency, CurrencyType, Erc20Token, Erc20TokenBuilder, NativeBuilder, ETH_ADDRESS,
        },
    },
    universal_router_sdk::universal_router_execute::build_execute_calldata,
};
use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{Address, U256},
    rpc::types::TransactionRequest,
};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct SwapParameter {
    pub chain_id: u64,
    pub rpc_url: String,
    // 输入代币地址 (如果是 ETH 则为 "ETH")
    pub input_token: String,
    // 输出代币地址
    pub output_token: String,
    // 输入金额
    pub input_human_amount: String,
    // 最小输出金额
    pub min_output_human_amount: String,
    // 接收地址
    pub recipient: String,
    // 交易类型 ("ExactInput" 或 "ExactOutput")
    pub trade_type: String,
    // 路由类型 ("V2" 或 "V3")
    pub route_type: String,
    // v3 路由费率
    pub fee_tier: Option<u32>,
    // v3 手续费
    pub fee_amount: Option<u16>,
    pub fee_recipient: Option<String>,
}

pub struct UniswapUnsignedTxGenerator;

impl UniswapUnsignedTxGenerator {
    pub async fn generate_swap_call_data(params: SwapParameter, deadline: u64) -> Result<String> {
        // 1. 构建币种 根据合约地址
        let input_currency = if params.input_token == ETH_ADDRESS {
            CurrencyType::Native(NativeBuilder::default().chain_id(params.chain_id).build()?)
        } else {
            CurrencyType::Token(
                Erc20TokenBuilder::default()
                    .address(Address::from_str(&params.input_token)?)
                    .build()?
                    .update_token_info(&params.rpc_url)
                    .await?,
            )
        };

        let output_currency = if params.output_token == ETH_ADDRESS {
            CurrencyType::Native(NativeBuilder::default().chain_id(params.chain_id).build()?)
        } else {
            CurrencyType::Token(
                Erc20TokenBuilder::default()
                    .address(Address::from_str(&params.output_token)?)
                    .build()?
                    .update_token_info(&params.rpc_url)
                    .await?,
            )
        };

        // 2. 构建金额
        let input_amount = CurrencyAmount {
            currency: input_currency.clone(),
            amount: Erc20Token::from_readable_amount(
                Decimal::from_str(&params.input_human_amount.to_string())?,
                input_currency.decimals(),
            ),
        };

        let output_amount = CurrencyAmount {
            currency: output_currency.clone(),
            amount: Erc20Token::from_readable_amount(
                Decimal::from_str(&params.min_output_human_amount.to_string())?,
                output_currency.decimals(),
            ),
        };

        // 3. 构建路由
        let route = match params.route_type.as_str() {
            "V2" => Route::V2 {
                input: input_currency.clone(),
                output: output_currency.clone(),
                path: vec![input_currency.clone(), output_currency.clone()],
            },
            "V3" => {
                let fee = params
                    .fee_tier
                    .ok_or_else(|| anyhow::anyhow!("V3 route requires fee_tier"))?;
                Route::V3 {
                    input: input_currency.clone(),
                    output: output_currency.clone(),
                    path: vec![input_currency.clone(), output_currency.clone()],
                    fee: vec![fee],
                }
            }
            _ => return Err(anyhow::anyhow!("Unsupported route type")),
        };

        // 4. 构建 Swap
        let swap = Swap {
            route,
            input_amount: input_amount.clone(),
            output_amount: output_amount.clone(),
        };

        // 5. 构建交易类型
        let trade_type = match params.trade_type.as_str() {
            "ExactInput" => TradeType::ExactInput,
            "ExactOutput" => TradeType::ExactOutput,
            _ => return Err(anyhow::anyhow!("Unsupported trade type")),
        };

        // 6. 构建路由交易
        let router_trade = match params.route_type.as_str() {
            "V2" => RouterTrade::V2 {
                swaps: vec![swap],
                trade_type,
                input_amount,
                output_amount,
            },
            "V3" => RouterTrade::V3 {
                swaps: vec![swap],
                trade_type,
                input_amount,
                output_amount,
            },
            _ => return Err(anyhow::anyhow!("Unsupported route type")),
        };

        // 7. 构建 SwapOptions
        let mut swap_options = SwapOptionsBuilder::default()
            .recipient(Some(Address::from_str(&params.recipient).unwrap()))
            .build()
            .unwrap();
        // if fee_recipient is set, set it
        if let Some(fee_recipient) = params.fee_recipient {
            // tip fee is 25
            let fee_option = FeeOptions {
                fee: params.fee_amount.unwrap_or(25),
                recipient: Address::from_str(&fee_recipient)?,
            };
            swap_options.fee = Some(fee_option);
        }

        // 8. 构建 Universal Trade
        let universal_trade = UniswapUniversalTrade::new(router_trade, swap_options)?;

        // 9. 编码命令
        let commands = universal_trade.encode()?;

        // 10. 构建最终 calldata
        let calldata = build_execute_calldata(commands, deadline);

        Ok(alloy::hex::encode(calldata))
    }

    // generate unsigned tx
    pub async fn generate_unsigned_tx(params: SwapParameter) -> Result<TransactionRequest> {
        let chain_id = ChainId::from(params.chain_id);
        // deadline 10 minutes
        let deadline = (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp();
        let calldata = Self::generate_swap_call_data(params.clone(), deadline as u64).await;
        match calldata {
            Ok(calldata) => {
                let mut tx = TransactionRequest::default()
                    .with_from(Address::from_str(&params.recipient)?)
                    .with_to(UniversalRouterAddress::from(chain_id).0)
                    .with_input(hex::decode(calldata)?);
                // if input is native set the value
                if params.input_token == ETH_ADDRESS {
                    tx.value = Some(
                        Erc20Token::from_readable_amount(
                            Decimal::from_str(&params.input_human_amount)?,
                            18,
                        )
                        .into(),
                    );
                }
                Ok(tx)
            }
            Err(e) => {
                panic!("Failed to generate swap call data: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        network::EthereumWallet,
        providers::{Provider, ProviderBuilder},
        signers::ledger::{HDPath, LedgerSigner},
    };

    use super::*;

    #[tokio::test]
    async fn test_generate_v2_swap_calldata_on_eth() {
        let mainet_rpc = "https://eth.llamarpc.com";
        let params = SwapParameter {
            chain_id: 1,
            rpc_url: mainet_rpc.to_string(),
            input_token: ETH_ADDRESS.to_string(),
            output_token: "0x576e2BeD8F7b46D34016198911Cdf9886f78bea7".to_string(),
            input_human_amount: "5".to_string(),
            min_output_human_amount: "3055.931071002".to_string(),
            recipient: "0x8De3459add8281882cf7b05f474F6E6fCf5909f6".to_string(),
            trade_type: "ExactInput".to_string(),
            route_type: "V2".to_string(),
            fee_tier: None,
            fee_amount: None,
            fee_recipient: None,
        };

        let calldata = UniswapUnsignedTxGenerator::generate_swap_call_data(params, 1730865534)
            .await
            .unwrap();
        assert_eq!(calldata, "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000672ae97e00000000000000000000000000000000000000000000000000000000000000020b080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000004563918244f4000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000008de3459add8281882cf7b05f474f6e6fcf5909f60000000000000000000000000000000000000000000000004563918244f40000000000000000000000000000000000000000000000000000000002c783af9a1a00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000576e2bed8f7b46d34016198911cdf9886f78bea7");
    }

    #[tokio::test]
    async fn test_generate_v3_swap_calldata_on_bsc() {
        //  https://bscscan.com/tx/0xbe9ecd560dc42e1dfdd552333b605f0a3feae00014e58c500dc45beae026faa7
        let bsc_mainet_rpc = "https://binance.llamarpc.com";
        let params = SwapParameter {
            chain_id: 56,
            rpc_url: bsc_mainet_rpc.to_string(),
            input_token: ETH_ADDRESS.to_string(),
            output_token: "0x6894cde390a3f51155ea41ed24a33a4827d3063d".to_string(),
            input_human_amount: "0.001".to_string(),
            min_output_human_amount: "13985.905612898336447520".to_string(),
            recipient: "0xC60DB0e0c6695c31d378f42ecc9fdFfa0E5a185E".to_string(),
            trade_type: "ExactInput".to_string(),
            route_type: "V3".to_string(),
            fee_tier: Some(3000),
            fee_amount: Some(25),
            fee_recipient: Some("0x1d786eed79c8ee62a43e6b5263ea424866a4bf34".to_string()),
        };

        let calldata = UniswapUnsignedTxGenerator::generate_swap_call_data(params, 1730989341)
            .await
            .unwrap();
        assert_eq!(calldata, "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000672ccd1d00000000000000000000000000000000000000000000000000000000000000040b000604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000038d7ea4c680000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000038d7ea4c68000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c000bb86894cde390a3f51155ea41ed24a33a4827d3063d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000006894cde390a3f51155ea41ed24a33a4827d3063d0000000000000000000000001d786eed79c8ee62a43e6b5263ea424866a4bf34000000000000000000000000000000000000000000000000000000000000001900000000000000000000000000000000000000000000000000000000000000600000000000000000000000006894cde390a3f51155ea41ed24a33a4827d3063d000000000000000000000000c60db0e0c6695c31d378f42ecc9fdffa0e5a185e0000000000000000000000000000000000000000000002f62d6e2e6d633f1c20");
    }

    #[tokio::test]
    async fn test_execute_v3_swap_on_bsc() -> Result<()> {
        //  https://bscscan.com/tx/0xef09a945e60d4437f6abbc72970174e82a2cbee3a44be7f2792441afce7fe263
        let bsc_mainet_rpc = "https://binance.llamarpc.com";
        let params = SwapParameter {
            chain_id: 56,
            rpc_url: bsc_mainet_rpc.to_string(),
            input_token: ETH_ADDRESS.to_string(),
            output_token: "0x6894cde390a3f51155ea41ed24a33a4827d3063d".to_string(),
            input_human_amount: "0.001".to_string(),
            min_output_human_amount: "15000.905612898336447520".to_string(),
            recipient: "0xC60DB0e0c6695c31d378f42ecc9fdFfa0E5a185E".to_string(),
            trade_type: "ExactInput".to_string(),
            route_type: "V3".to_string(),
            fee_tier: Some(3000),
            fee_amount: Some(25),
            fee_recipient: Some("0x1d786eed79c8ee62a43e6b5263ea424866a4bf34".to_string()),
        };

        let _unsigned_tx = UniswapUnsignedTxGenerator::generate_unsigned_tx(params)
            .await
            .unwrap();
        // let signer = LedgerSigner::new(HDPath::LedgerLive(0), Some(ChainId::Bnb as u64)).await?;
        // let wallet = EthereumWallet::from(signer);
        // let provider = ProviderBuilder::new()
        //     .with_recommended_fillers()
        //     .wallet(wallet)
        //     .on_http(bsc_mainet_rpc.parse()?);
        // let tx_hash = provider
        //     .send_transaction(unsigned_tx)
        //     .await?
        //     .watch()
        //     .await?;
        // println!("Sent transaction: {tx_hash}");
        assert!(true);
        Ok(())
    }
}
