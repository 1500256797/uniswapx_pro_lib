use alloy::{
    primitives::{Address, U256},
    providers::ProviderBuilder,
};
use alloy_sol_types::SolCall;
use derive_builder::Builder;
use std::sync::Arc;

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;

use alloy::{primitives::utils::format_units, sol};

use super::weth9::Weth9;
use crate::prelude::*;
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ERC20,
    "src/abi/erc20.json"
);
pub const ETH_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

#[derive(Debug, Clone, Builder)]
pub struct Erc20Token {
    #[builder(default = "1")]
    pub chain_id: u64,
    pub address: Address,
    #[builder(default = "18")]
    pub decimals: u8,
    #[builder(default = "Some(\"Unknown\".to_string())")]
    pub symbol: Option<String>,
    #[builder(default = "Some(\"Unknown\".to_string())")]
    pub name: Option<String>,
    #[builder(default = "None")]
    pub buy_fee_bps: Option<u64>,
    #[builder(default = "None")]
    pub sell_fee_bps: Option<u64>,
    #[builder(default = "false")]
    pub is_native: bool,
    #[builder(default = "true")]
    pub is_token: bool,
}

// update decimals name symbol from rpc url
impl Erc20Token {
    pub async fn update_token_info(mut self, rpc_url: &str) -> Result<Self> {
        let provider = ProviderBuilder::new().on_builtin(&rpc_url).await?;
        let client = Arc::new(provider);
        let contract = ERC20::new(self.address, client);
        let decimals = contract.decimals().call().await?._0;
        let symbol = contract.symbol().call().await?._0;
        let name = contract.name().call().await?._0;
        self.decimals = decimals as u8;
        self.symbol = Some(symbol);
        self.name = Some(name);
        Ok(self)
    }

    pub fn from_readable_amount(amount_in: Decimal, decimals: u8) -> U256 {
        let factor = Decimal::new(10_i64.pow(decimals as u32), 0);
        U256::from((amount_in * factor).to_u128().unwrap())
    }
    pub fn to_readable_amount(amount_in: U256, decimals: u8) -> f64 {
        let num: String = format_units(amount_in, decimals).unwrap();
        num.parse::<f64>().unwrap()
    }

    pub fn approve_call_data(&self, spender: Address, human_readable_amount: &str) -> Vec<u8> {
        let amount = Self::from_readable_amount(
            Decimal::from_str(human_readable_amount).unwrap(),
            self.decimals,
        );
        let approve_call_data = ERC20::approveCall::abi_encode(&ERC20::approveCall {
            _spender: spender,
            _value: amount,
        });
        approve_call_data
    }
}

#[derive(Debug, Clone, Builder)]
pub struct Native {
    #[builder(default = "1")]
    pub chain_id: u64,
    #[builder(default = "18")]
    pub decimals: u8,
    #[builder(default = "Some(\"ETH\".to_string())")]
    pub symbol: Option<String>,
    #[builder(default = "Some(\"Ethereum\".to_string())")]
    pub name: Option<String>,
    #[builder(default = "true")]
    pub is_native: bool,
    #[builder(default = "false")]
    pub is_token: bool,
}

#[derive(Debug, Clone)]
pub enum CurrencyType {
    Native(Native),
    Token(Erc20Token),
}

pub trait Currency {
    fn decimals(&self) -> u8;
    fn symbol(&self) -> Option<&str>;
    fn name(&self) -> Option<&str>;
    fn chain_id(&self) -> u64;
    fn is_native(&self) -> bool;
    fn is_token(&self) -> bool;
    fn wrapped_address(&self) -> Address;
}

impl Currency for CurrencyType {
    fn decimals(&self) -> u8 {
        match self {
            CurrencyType::Native(native) => native.decimals,
            CurrencyType::Token(token) => token.decimals,
        }
    }

    fn symbol(&self) -> Option<&str> {
        match self {
            CurrencyType::Native(native) => native.symbol.as_deref(),
            CurrencyType::Token(token) => token.symbol.as_deref(),
        }
    }

    fn name(&self) -> Option<&str> {
        match self {
            CurrencyType::Native(native) => native.name.as_deref(),
            CurrencyType::Token(token) => token.name.as_deref(),
        }
    }

    fn chain_id(&self) -> u64 {
        match self {
            CurrencyType::Native(native) => native.chain_id,
            CurrencyType::Token(token) => token.chain_id,
        }
    }

    fn is_native(&self) -> bool {
        matches!(self, CurrencyType::Native(_))
    }

    fn is_token(&self) -> bool {
        matches!(self, CurrencyType::Token(_))
    }

    fn wrapped_address(&self) -> Address {
        match self {
            CurrencyType::Native(native) => Weth9::from(native.chain_id).0,
            CurrencyType::Token(token) => token.address.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use std::str::FromStr;

    #[test]
    fn test_erc20_token() {
        // 创建 USDC token
        let usdc = Erc20TokenBuilder::default()
            .chain_id(1)
            .address(Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap())
            .decimals(6)
            .symbol(Some("USDC".to_string()))
            .name(Some("USD Coin".to_string()))
            .build()
            .unwrap();

        // 使用 Token 的行为
        assert_eq!(usdc.is_token, true);
        assert_eq!(usdc.is_native, false);
        // 检查地址
        assert_eq!(
            usdc.address,
            Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap()
        );
        assert_eq!(usdc.chain_id, 1);
        assert_eq!(usdc.decimals, 6);
        assert_eq!(usdc.symbol, Some("USDC".to_string()));
        assert_eq!(usdc.name, Some("USD Coin".to_string()));
    }

    #[test]
    fn test_native_currency() {
        let native = NativeBuilder::default()
            .chain_id(1)
            .decimals(18)
            .symbol(Some("ETH".to_string()))
            .name(Some("Ethereum".to_string()))
            .build()
            .unwrap();
        assert_eq!(native.is_native, true);
        assert_eq!(native.is_token, false);
        assert_eq!(native.chain_id, 1);
        assert_eq!(native.decimals, 18);
        assert_eq!(native.symbol, Some("ETH".to_string()));
        assert_eq!(native.name, Some("Ethereum".to_string()));
    }

    #[test]
    fn test_amount_conversion() {
        let amount = Erc20Token::from_readable_amount(dec!(13985.905612898336447520), 18);
        assert_eq!(amount, U256::from_str("13985905612898336447520").unwrap());
        let readable_amount = Erc20Token::to_readable_amount(amount, 18);
        assert_eq!(readable_amount, 13985.905612898336447520);
    }

    #[tokio::test]
    async fn test_approve_call_data() -> Result<()> {
        let meme = Erc20TokenBuilder::default()
            .address(Address::from_str(
                "0x6894CDe390a3f51155ea41Ed24a33A4827d3063D",
            )?)
            .build()?
            .update_token_info("https://binance.llamarpc.com")
            .await?;
        let permit2_address = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
        let approve_call_data = meme.approve_call_data(
            Address::from_str(permit2_address)?,
            "32655.382378191657965278",
        );
        assert_eq!(
            "095ea7b3000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba30000000000000000000000000000000000000000000006ea4077a955987d16de",
            hex::encode(approve_call_data)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_approve_amount_to_perimit2() -> Result<()> {
        let meme = Erc20TokenBuilder::default()
            .address(Address::from_str(
                "0x35c8941c294E9d60E0742CB9f3d58c0D1Ba2DEc4",
            )?)
            .build()?
            .update_token_info("https://rpc.flashbots.net/fast")
            .await?;
        let permit2_address = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
        let approve_call_data =
            meme.approve_call_data(Address::from_str(permit2_address)?, "60.3968");
        assert_eq!(
            "095ea7b3000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba3000000000000000000000000000000000000000000000003462c899aa2500000",
            hex::encode(approve_call_data)
        );
        Ok(())
    }
}
