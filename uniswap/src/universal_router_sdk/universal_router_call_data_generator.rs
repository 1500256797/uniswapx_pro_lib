// refactor universal router sdk by rust
// https://github.com/Uniswap/sdks/blob/8b2649bf956f0cae69d58b8e3a4fd4cc8f164756/sdks/universal-router-sdk/src/entities/actions/uniswap.ts#L45
use crate::{
    core_sdk::{
        chain::ChainId,
        currency::{Currency, CurrencyType, ETH_ADDRESS},
        weth9::Weth9,
    },
    universal_router_sdk::universal_router_commands::{
        PayPortionParams, SweepParams, TransferParams, UniswapV3UniversalRouterCommand,
        UnwrapWethParams, V2SwapExactInParams, V2SwapExactOutParams, WrapEthParams,
    },
};
use alloy::primitives::{Address, U256};
use anyhow::Result;
use derive_builder::Builder;
use std::{default, str::FromStr};

use super::universal_router_commands::{
    encode_path, Permit2PermitParams, V3SwapExactInParams, V3SwapExactOutParams,
};

#[derive(Debug, Clone, Default)]
pub struct FlatFeeOptions {
    pub amount: U256,
    pub recipient: Address,
}

#[derive(Debug, Clone, Builder)]
pub struct FeeOptions {
    /// The percent of the output that will be taken as a fee.
    pub fee: u16,
    /// The recipient of the fee.
    pub recipient: Address,
}

// the existing router permit object doesn't include enough data for permit2
// so we extend swap options with the permit2 permit
// when safe mode is enabled, the SDK will add an extra ETH sweep for security
// when useRouterBalance is enabled the SDK will use the balance in the router for the swap
#[derive(Debug, Clone, Builder)]
pub struct SwapOptions {
    #[builder(default)]
    pub use_router_balance: Option<bool>,
    #[builder(setter(strip_option), default)]
    pub input_token_permit: Option<Permit2PermitParams>,
    #[builder(setter(strip_option), default)]
    pub flat_fee: Option<FlatFeeOptions>,
    #[builder(setter(strip_option), default)]
    pub fee: Option<FeeOptions>,
    #[builder(setter(strip_option), default)]
    pub safe_mode: Option<bool>,
    pub recipient: Option<Address>,
}
#[derive(Debug, Clone)]
pub enum TradeType {
    ExactInput,
    ExactOutput,
}

#[derive(Debug, Clone, Builder)]
pub struct CurrencyAmount {
    pub currency: CurrencyType,
    pub amount: U256,
}

#[derive(Debug, Clone)]
pub enum Route {
    V2 {
        input: CurrencyType,
        output: CurrencyType,
        path: Vec<CurrencyType>,
    },
    V3 {
        input: CurrencyType,
        output: CurrencyType,
        path: Vec<CurrencyType>,
        fee: Vec<u32>,
    },
    V4 {
        input: CurrencyType,
        output: CurrencyType,
        path: Vec<CurrencyType>,
    },
}

impl Route {
    pub fn path(&self) -> &Vec<CurrencyType> {
        match self {
            Route::V2 { path, .. } => path,
            Route::V3 { path, .. } => path,
            Route::V4 { path, .. } => path,
        }
    }

    pub fn input(&self) -> &CurrencyType {
        match self {
            Route::V2 { input, .. } => input,
            Route::V3 { input, .. } => input,
            Route::V4 { input, .. } => input,
        }
    }

    pub fn output(&self) -> &CurrencyType {
        match self {
            Route::V2 { output, .. } => output,
            Route::V3 { output, .. } => output,
            Route::V4 { output, .. } => output,
        }
    }

    pub fn fee(&self) -> Vec<u32> {
        match self {
            Route::V3 { fee, .. } => fee.clone(),
            _ => vec![],
        }
    }
}

#[derive(Debug, Clone, Builder)]
pub struct Swap {
    pub route: Route,
    pub input_amount: CurrencyAmount,
    pub output_amount: CurrencyAmount,
}

#[derive(Debug, Clone, Default)]
pub enum RouterActionType {
    #[default]
    UniswapTrade,
    UnwrapWETH,
}

pub const SENDER_AS_RECIPIENT: &str = "0x0000000000000000000000000000000000000001";
pub const ROUTER_AS_RECIPIENT: &str = "0x0000000000000000000000000000000000000002";
// 路由交易枚举

#[derive(Debug, Clone)]
pub enum RouterTrade {
    // V2 交易
    V2 {
        swaps: Vec<Swap>,
        trade_type: TradeType,
        input_amount: CurrencyAmount,
        output_amount: CurrencyAmount,
    },
    // V3 交易
    V3 {
        swaps: Vec<Swap>,
        trade_type: TradeType,
        input_amount: CurrencyAmount,
        output_amount: CurrencyAmount,
    },
    // V4 交易
    V4 {
        swaps: Vec<Swap>,
        trade_type: TradeType,
        input_amount: CurrencyAmount,
        output_amount: CurrencyAmount,
    },
    // 混合交易
    Mixed {
        swaps: Vec<Swap>,
        trade_type: TradeType,
        input_amount: CurrencyAmount,
        output_amount: CurrencyAmount,
    },
}

#[derive(Debug, Clone, Builder)]
pub struct UniswapUniversalTrade {
    #[builder(default)]
    pub trade_type: RouterActionType,
    #[builder(setter(skip))]
    pub payer_is_user: bool,
    pub trade: RouterTrade,
    pub options: SwapOptions,
}

impl UniswapUniversalTrade {
    pub fn new(trade: RouterTrade, mut options: SwapOptions) -> Result<Self> {
        // 如果同时设置了百分比小费和固定小费，则返回错误
        if options.fee.is_some() && options.flat_fee.is_some() {
            panic!("Only one fee option permitted");
        }
        // 确定谁是支付者
        let payer_is_user = if Self::input_requires_wrap(&trade) {
            // 情况1: 如果需要将ETH 包装成 WETH 那么就需要用户先把ETH 发送到路由器，然后由路由器来支付
            false
        } else if options.use_router_balance.unwrap_or(false) {
            // 情况2: 如果打开了 use_router_balance 那么就由路由器来支付
            false
        } else {
            // 情况3: 否则就由用户来支付 比如直接支付erc20 token
            true
        };
        // 设置接收者 如果没有设置接收者 那么就使用msg.sender 作为接收者
        let recipient = options
            .recipient
            .unwrap_or(Address::from_str(SENDER_AS_RECIPIENT).unwrap());
        options.recipient = Some(recipient);
        Ok(Self {
            trade_type: RouterActionType::UniswapTrade,
            payer_is_user,
            trade,
            options,
        })
    }

    pub fn is_all_v4(trade: &RouterTrade) -> bool {
        // 如果有任何一个swap 不是v4 那么就返回false
        // 只有全部都是v4 才返回true
        // 因为v4 是唯一的 所以直接判断trade 的类型即可
        matches!(trade, RouterTrade::V4 { .. })
    }

    pub fn input_requires_wrap(trade: &RouterTrade) -> bool {
        let (swaps, input_amount) = match &trade {
            RouterTrade::V2 {
                swaps,
                input_amount,
                ..
            }
            | RouterTrade::V3 {
                swaps,
                input_amount,
                ..
            }
            | RouterTrade::V4 {
                swaps,
                input_amount,
                ..
            }
            | RouterTrade::Mixed {
                swaps,
                input_amount,
                ..
            } => (swaps, input_amount),
        };

        let input_requires_wrap = if !Self::is_all_v4(&trade) {
            // 情况1: 非 V4 协议 (V2 或 V3)
            // 如果输入是原生代币(ETH)，就需要包装成 WETH
            // 如果swap 中含有v2 或者 v3 并且输入的token 是native 那么就需要包装
            input_amount.currency.is_native()
        } else {
            // 情况2: 全部都是v4 协议
            input_amount.currency.is_native() && !swaps[0].route.input().is_native()
        };
        input_requires_wrap
    }

    pub fn output_requires_unwrap(trade: &RouterTrade) -> bool {
        let (swaps, output_amount) = match trade {
            RouterTrade::V2 {
                swaps,
                output_amount,
                ..
            }
            | RouterTrade::V3 {
                swaps,
                output_amount,
                ..
            }
            | RouterTrade::V4 {
                swaps,
                output_amount,
                ..
            }
            | RouterTrade::Mixed {
                swaps,
                output_amount,
                ..
            } => (swaps, output_amount),
        };

        if !Self::is_all_v4(&trade) {
            // 如果不涉及v4 协议 那么输出是native 就需要unwarp
            output_amount.currency.is_native()
        } else {
            // 拿到swap 的第一个元素
            let first_swap = &swaps[0];
            // 匹配成v4 并且输出是native
            let output = match &first_swap.route {
                Route::V4 { output, .. } => output,
                _ => return false,
            };
            // 如果涉及v4 协议 那么输出是native 并且第一个swap 的输出不是native 就需要unwarp
            output_amount.currency.is_native() && !output.is_native()
        }
    }
    pub fn encode(&self) -> Result<Vec<UniswapV3UniversalRouterCommand>> {
        let mut commands: Vec<UniswapV3UniversalRouterCommand> = vec![];
        // 处理输入代币包装
        let (input_amount, output_amount, trade_type, swaps) = match &self.trade {
            RouterTrade::V2 {
                input_amount,
                output_amount,
                trade_type,
                swaps,
                ..
            }
            | RouterTrade::V3 {
                input_amount,
                output_amount,
                trade_type,
                swaps,
                ..
            }
            | RouterTrade::V4 {
                input_amount,
                output_amount,
                trade_type,
                swaps,
                ..
            }
            | RouterTrade::Mixed {
                input_amount,
                output_amount,
                trade_type,
                swaps,
                ..
            } => (input_amount, output_amount, trade_type, swaps),
        };
        if Self::input_requires_wrap(&self.trade) {
            commands.push(UniswapV3UniversalRouterCommand::WrapEth(WrapEthParams {
                recipient: Address::from_str(ROUTER_AS_RECIPIENT).unwrap(),
                amount: input_amount.amount,
            }));
        }

        // 如果需要permit2 那么就把它编码进去
        if let Some(permit) = &self.options.input_token_permit {
            commands.push(UniswapV3UniversalRouterCommand::Permit2Permit(
                permit.clone(),
            ));
        }
        // 检查是否需要聚合滑点检查
        let perform_aggregated_slippage_check =
            matches!(trade_type, TradeType::ExactInput) && swaps.len() > 2;

        // 判断路由器是否需要托管你的token
        // 如果需要聚合滑点检查 或者 输出需要unwarp 或者 有小费 那么路由器就需要托管你的token
        let router_must_custody = perform_aggregated_slippage_check
            || Self::output_requires_unwrap(&self.trade)
            || self.options.flat_fee.is_some()
            || self.options.fee.is_some();

        // 处理每个 swap
        for swap in swaps {
            match swap.route {
                Route::V2 { .. } => Self::add_v2_swap(
                    &mut commands,
                    trade_type,
                    &self.options,
                    router_must_custody,
                    swap,
                ),
                Route::V3 { .. } => Self::add_v3_swap(
                    &mut commands,
                    trade_type,
                    &self.options,
                    router_must_custody,
                    swap,
                ),
                Route::V4 { .. } => todo!(),
            }
        }

        // 计算考虑滑点的最小输出金额
        let minimum_amount_out = output_amount;

        // 如果路由器需要托管代币
        if router_must_custody {
            // 处理百分比费用
            if let Some(fee) = &self.options.fee {
                let fee_bips = U256::from(fee.fee);

                // 添加支付百分比费用的命令
                commands.push(UniswapV3UniversalRouterCommand::PayPortion(
                    PayPortionParams {
                        token: output_amount.currency.wrapped_address(),
                        recipient: fee.recipient,
                        basis_points: fee_bips,
                    },
                ));

                // 如果是精确输出交易，需要调整最小输出金额
                if matches!(trade_type, TradeType::ExactOutput) {
                    let fee_amount = minimum_amount_out
                        .amount
                        .checked_mul(fee_bips)
                        .unwrap()
                        .checked_div(U256::from(10000))
                        .unwrap();
                    minimum_amount_out.amount.checked_sub(fee_amount).unwrap();
                }
            }

            // 处理固定费用
            if let Some(flat_fee) = &self.options.flat_fee {
                let fee_amount = flat_fee.amount;

                // 检查费用是否超过最小输出金额
                if minimum_amount_out.amount < fee_amount {
                    panic!("Flat fee amount greater than minimumAmountOut");
                }

                // 添加转账固定费用的命令
                commands.push(UniswapV3UniversalRouterCommand::Transfer(TransferParams {
                    token: output_amount.currency.wrapped_address(),
                    recipient: flat_fee.recipient,
                    amount: fee_amount,
                }));

                // 如果是精确输出交易，需要调整最小输出金额
                if matches!(trade_type, TradeType::ExactOutput) {
                    minimum_amount_out.amount.checked_sub(fee_amount).unwrap();
                }
            }

            // 处理剩余代币的发送
            if Self::output_requires_unwrap(&self.trade) {
                // 如果输出需要解包（WETH -> ETH）
                commands.push(UniswapV3UniversalRouterCommand::UnwrapWeth(
                    UnwrapWethParams {
                        recipient: self
                            .options
                            .recipient
                            .unwrap_or(Address::from_str(SENDER_AS_RECIPIENT).unwrap()),
                        min_amount_out: minimum_amount_out.amount,
                    },
                ));
            } else {
                // 直接发送代币
                commands.push(UniswapV3UniversalRouterCommand::Sweep(SweepParams {
                    token: output_amount.currency.wrapped_address(),
                    recipient: self
                        .options
                        .recipient
                        .unwrap_or(Address::from_str(SENDER_AS_RECIPIENT).unwrap()),
                    min_amount_out: minimum_amount_out.amount,
                }));
            }
        }

        // 如果输入需要包装 并且 是精确输出交易 或者 有部分成交的风险
        // https://github.com/Uniswap/sdks/blob/8b2649bf956f0cae69d58b8e3a4fd4cc8f164756/sdks/universal-router-sdk/src/entities/actions/uniswap.ts#L194
        if Self::input_requires_wrap(&self.trade) && matches!(trade_type, TradeType::ExactOutput) {
            // 对于使用原生货币作为输入的精确输出交易
            // 需要将剩余的 WETH 返回给用户
            commands.push(UniswapV3UniversalRouterCommand::UnwrapWeth(
                UnwrapWethParams {
                    recipient: self
                        .options
                        .recipient
                        .unwrap_or(Address::from_str(SENDER_AS_RECIPIENT).unwrap()),
                    min_amount_out: U256::ZERO,
                },
            ));
        }

        // 安全模式：清扫所有剩余的 ETH
        if self.options.safe_mode.unwrap_or(false) {
            commands.push(UniswapV3UniversalRouterCommand::Sweep(SweepParams {
                token: Address::from_str(ETH_ADDRESS).unwrap(),
                recipient: self
                    .options
                    .recipient
                    .unwrap_or(Address::from_str(SENDER_AS_RECIPIENT).unwrap()),
                min_amount_out: U256::ZERO,
            }));
        }

        Ok(commands)
    }
    pub fn add_v3_swap(
        commands: &mut Vec<UniswapV3UniversalRouterCommand>,
        trade_type: &TradeType,
        options: &SwapOptions,
        router_must_custody: bool,
        swap: &Swap,
    ) -> () {
        // 设置接收者地址
        let recipient = if router_must_custody {
            Address::from_str(ROUTER_AS_RECIPIENT).unwrap()
        } else {
            options.recipient.unwrap()
        };

        // 编码路径
        let path = encode_path(
            &swap
                .route
                .path()
                .iter()
                .map(|c| c.wrapped_address())
                .collect::<Vec<Address>>(),
            &swap.route.fee(),
        );

        match trade_type {
            TradeType::ExactInput => {
                commands.push(UniswapV3UniversalRouterCommand::V3SwapExactIn(
                    V3SwapExactInParams {
                        recipient,
                        amount_in: swap.input_amount.amount,
                        min_amount_out: if router_must_custody {
                            U256::ZERO
                        } else {
                            swap.output_amount.amount
                        },
                        path,
                        use_permit2: options.input_token_permit.is_some(),
                    },
                ));
            }
            TradeType::ExactOutput => {
                commands.push(UniswapV3UniversalRouterCommand::V3SwapExactOut(
                    V3SwapExactOutParams {
                        recipient,
                        amount_out: swap.output_amount.amount,
                        max_amount_in: swap.input_amount.amount,
                        path,
                        use_permit2: options.input_token_permit.is_some(),
                    },
                ));
            }
        }
    }
    pub fn add_v2_swap(
        commands: &mut Vec<UniswapV3UniversalRouterCommand>,
        trade_type: &TradeType,
        options: &SwapOptions,
        router_must_custody: bool,
        swap: &Swap,
    ) -> () {
        match trade_type {
            TradeType::ExactInput => {
                // if native, we have to unwrap so keep in the router for now
                // 如果输入的币是native币，我们需要wrap一下，然后使用 ROUTER_AS_RECIPIENT 作为接收者
                let recipient = if router_must_custody {
                    Address::from_str(ROUTER_AS_RECIPIENT).unwrap()
                } else {
                    options.recipient.unwrap()
                };
                let params = UniswapV3UniversalRouterCommand::V2SwapExactIn(V2SwapExactInParams {
                    amount_in: swap.input_amount.amount,
                    min_amount_out: swap.output_amount.amount,
                    path: swap
                        .route
                        .path()
                        .iter()
                        .map(|c| c.wrapped_address())
                        .collect(),
                    use_permit2: options.input_token_permit.is_some(),
                    recipient,
                });
                commands.push(params);
            }
            TradeType::ExactOutput => {
                commands.push(UniswapV3UniversalRouterCommand::V2SwapExactOut(
                    V2SwapExactOutParams {
                        amount_out: swap.output_amount.amount,
                        max_amount_in: swap.input_amount.amount,
                        path: swap
                            .route
                            .path()
                            .iter()
                            .map(|c| c.wrapped_address())
                            .collect(),
                        recipient: if router_must_custody {
                            Address::from_str(ROUTER_AS_RECIPIENT).unwrap()
                        } else {
                            options.recipient.unwrap()
                        },
                        use_permit2: false,
                    },
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;

    use alloy::hex;

    use crate::{
        core_sdk::currency::{Erc20TokenBuilder, NativeBuilder},
        universal_router_sdk::{
            universal_router_commands::{PermitDetails, PermitSingle},
            universal_router_execute::{build_execute_calldata, execute_decode},
        },
    };

    use super::*;

    #[test]
    pub fn test_v2_swap_exact_in_eg1() {
        let eth = NativeBuilder::default().build().unwrap();
        let meme = Erc20TokenBuilder::default()
            .address(Address::from_str("0xc328a59E7321747aEBBc49FD28d1b32C1af8d3b2").unwrap())
            .decimals(9)
            .symbol(Some("PHIL".to_string()))
            .name(Some("PHIL".to_string()))
            .build()
            .unwrap();
        let swap = Swap {
            input_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(210000000000000000u128),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Token(meme.clone()),
                amount: U256::from(0u128),
            },
            route: Route::V2 {
                input: CurrencyType::Native(eth.clone()),
                output: CurrencyType::Token(meme.clone()),
                path: vec![
                    CurrencyType::Native(eth.clone()),
                    CurrencyType::Token(meme.clone()),
                ],
            },
        };
        let router_trade = RouterTrade::V2 {
            swaps: vec![swap.clone()],
            trade_type: TradeType::ExactInput,
            input_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(210000000000000000u128),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Token(meme.clone()),
                amount: U256::from(13582173608366753298733u128),
            },
        };
        let options = SwapOptions {
            use_router_balance: Some(false),
            input_token_permit: None,
            flat_fee: None,
            fee: Some(FeeOptions {
                fee: 25,
                recipient: Address::from_str("0x000000fee13a103a10d593b9ae06b3e05f2e7e1c").unwrap(),
            }),
            safe_mode: None,
            recipient: Some(
                Address::from_str("0x9AdaF4fCD9a248e54051333584521E8231CFE2ad").unwrap(),
            ),
        };

        // unswap trade
        let unswap_trade = UniswapUniversalTrade::new(router_trade, options).unwrap();
        let commands = unswap_trade.encode().unwrap();
        let data = build_execute_calldata(commands, 1730734598u64);
        assert_eq!("3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000006728ea0600000000000000000000000000000000000000000000000000000000000000040b080604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000002ea11e32ad500000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000002ea11e32ad50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000c328a59e7321747aebbc49fd28d1b32c1af8d3b20000000000000000000000000000000000000000000000000000000000000060000000000000000000000000c328a59e7321747aebbc49fd28d1b32c1af8d3b2000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c00000000000000000000000000000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000c328a59e7321747aebbc49fd28d1b32c1af8d3b20000000000000000000000009adaf4fcd9a248e54051333584521e8231cfe2ad0000000000000000000000000000000000000000000002e04a85f75ea1d5b92d", hex::encode(data));
    }

    #[test]
    pub fn test_v2_swap_exact_in_eg2() {
        let eth = NativeBuilder::default().build().unwrap();
        let meme = Erc20TokenBuilder::default()
            .address(Address::from_str("0x6A7eFF1e2c355AD6eb91BEbB5ded49257F3FED98").unwrap())
            .decimals(18)
            .symbol(Some("OPSEC".to_string()))
            .name(Some("OPSEC".to_string()))
            .build()
            .unwrap();
        let swap = Swap {
            input_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(50000000000000000u128),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Token(meme.clone()),
                amount: U256::from(0u128),
            },
            route: Route::V2 {
                input: CurrencyType::Native(eth.clone()),
                output: CurrencyType::Token(meme.clone()),
                path: vec![
                    CurrencyType::Native(eth.clone()),
                    CurrencyType::Token(meme.clone()),
                ],
            },
        };
        let router_trade = RouterTrade::V2 {
            swaps: vec![swap.clone()],
            trade_type: TradeType::ExactInput,
            input_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(50000000000000000u128),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Token(meme.clone()),
                amount: U256::from(14288876239108097656304u128),
            },
        };
        let options = SwapOptions {
            use_router_balance: Some(false),
            input_token_permit: None,
            flat_fee: None,
            fee: Some(FeeOptions {
                fee: 25,
                recipient: Address::from_str("0x000000fee13a103a10d593b9ae06b3e05f2e7e1c").unwrap(),
            }),
            safe_mode: None,
            recipient: Some(
                Address::from_str("0x7F5C2032211407b822e8B4aa7cC59bE2a9f792C4").unwrap(),
            ),
        };
        // unswap trade
        let unswap_trade = UniswapUniversalTrade::new(router_trade, options).unwrap();
        let commands = unswap_trade.encode().unwrap();
        let data = build_execute_calldata(commands, 1730780632);
        assert_eq!(
            "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000067299dd800000000000000000000000000000000000000000000000000000000000000040b080604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000b1a2bc2ec500000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000b1a2bc2ec50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000006a7eff1e2c355ad6eb91bebb5ded49257f3fed9800000000000000000000000000000000000000000000000000000000000000600000000000000000000000006a7eff1e2c355ad6eb91bebb5ded49257f3fed98000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c000000000000000000000000000000000000000000000000000000000000001900000000000000000000000000000000000000000000000000000000000000600000000000000000000000006a7eff1e2c355ad6eb91bebb5ded49257f3fed980000000000000000000000007f5c2032211407b822e8b4aa7cc59be2a9f792c400000000000000000000000000000000000000000000030699fe11c205b745f0",
            hex::encode(data)
        );
    }

    #[test]
    pub fn test_mix_v2_v3_swap_exact_in() {
        // https://etherscan.io/tx/0x06ce886b85ed4c8d314565d84efea5979ebceba00287f108a79f613d1136c717
        let eth = NativeBuilder::default().build().unwrap();
        let meme = Erc20TokenBuilder::default()
            .address(Address::from_str("0x1121AcC14c63f3C872BFcA497d10926A6098AAc5").unwrap())
            .decimals(18)
            .symbol(Some("DOGE".to_string()))
            .name(Some("DOGE".to_string()))
            .build()
            .unwrap();

        let router_trade = RouterTrade::Mixed {
            swaps: vec![
                Swap {
                    input_amount: CurrencyAmount {
                        currency: CurrencyType::Native(eth.clone()),
                        amount: U256::from(3600000000000000000u128),
                    },
                    output_amount: CurrencyAmount {
                        currency: CurrencyType::Token(meme.clone()),
                        amount: U256::from(0u128),
                    },
                    route: Route::V2 {
                        input: CurrencyType::Native(eth.clone()),
                        output: CurrencyType::Token(meme.clone()),
                        path: vec![
                            CurrencyType::Native(eth.clone()),
                            CurrencyType::Token(meme.clone()),
                        ],
                    },
                },
                Swap {
                    input_amount: CurrencyAmount {
                        currency: CurrencyType::Native(eth.clone()),
                        amount: U256::from(400000000000000000u128),
                    },
                    output_amount: CurrencyAmount {
                        currency: CurrencyType::Token(meme.clone()),
                        amount: U256::from(0u128),
                    },
                    route: Route::V3 {
                        input: CurrencyType::Native(eth.clone()),
                        output: CurrencyType::Token(meme.clone()),
                        path: vec![
                            CurrencyType::Native(eth.clone()),
                            CurrencyType::Token(meme.clone()),
                        ],
                        fee: vec![10000],
                    },
                },
            ],
            trade_type: TradeType::ExactInput,
            input_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(4000000000000000000u128),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Token(meme.clone()),
                amount: U256::from(143293272479182942806137u128),
            },
        };

        let options = SwapOptions {
            use_router_balance: Some(false),
            input_token_permit: None,
            flat_fee: None,
            fee: Some(FeeOptions {
                fee: 25,
                recipient: Address::from_str("0x000000fee13a103a10d593b9ae06b3e05f2e7e1c").unwrap(),
            }),
            safe_mode: None,
            recipient: Some(
                Address::from_str("0xC0603f5cca3d74bC8049614F8089C5A165C3160E").unwrap(),
            ),
        };

        // unswap trade
        let unswap_trade = UniswapUniversalTrade::new(router_trade, options).unwrap();
        let commands = unswap_trade.encode().unwrap();
        let data = build_execute_calldata(commands, 1730860015);
        assert_eq!(
            "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000672ad3ef00000000000000000000000000000000000000000000000000000000000000050b08000604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000034000000000000000000000000000000000000000000000000000000000000003c0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000003782dace9d9000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000031f5c4ed27680000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000001121acc14c63f3c872bfca497d10926a6098aac500000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000058d15e176280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc20027101121acc14c63f3c872bfca497d10926a6098aac500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000001121acc14c63f3c872bfca497d10926a6098aac5000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c000000000000000000000000000000000000000000000000000000000000001900000000000000000000000000000000000000000000000000000000000000600000000000000000000000001121acc14c63f3c872bfca497d10926a6098aac5000000000000000000000000c0603f5cca3d74bc8049614f8089c5a165c3160e000000000000000000000000000000000000000000001e57f1a137857cd2a079",
            hex::encode(data)
        );
    }

    #[test]
    pub fn test_v2_swap_exact_in_trump() {
        // https://etherscan.io/tx/0x77e26337061aee5cb227c69deb6121872fc38fbe7576428d8927c4ca890acf3d
        // 0x0b08
        let eth = NativeBuilder::default().build().unwrap();
        let meme = Erc20TokenBuilder::default()
            .address(Address::from_str("0x576e2BeD8F7b46D34016198911Cdf9886f78bea7").unwrap())
            .decimals(9)
            .symbol(Some("TRUMP".to_string()))
            .name(Some("TRUMP".to_string()))
            .build()
            .unwrap();
        let router_trade = RouterTrade::V2 {
            swaps: vec![Swap {
                input_amount: CurrencyAmount {
                    currency: CurrencyType::Native(eth.clone()),
                    amount: U256::from(5000000000000000000u128),
                },
                output_amount: CurrencyAmount {
                    currency: CurrencyType::Token(meme.clone()),
                    amount: U256::from(3055931071002u128),
                },
                route: Route::V2 {
                    input: CurrencyType::Native(eth.clone()),
                    output: CurrencyType::Token(meme.clone()),
                    path: vec![
                        CurrencyType::Native(eth.clone()),
                        CurrencyType::Token(meme.clone()),
                    ],
                },
            }],
            trade_type: TradeType::ExactInput,
            input_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(5000000000000000000 as u128),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Token(meme.clone()),
                amount: U256::from(3055931071002 as u128),
            },
        };
        let options = SwapOptions {
            use_router_balance: Some(false),
            input_token_permit: None,
            flat_fee: None,
            fee: None,
            safe_mode: None,
            recipient: Some(
                Address::from_str("0x8De3459add8281882cf7b05f474F6E6fCf5909f6").unwrap(),
            ),
        };
        // unswap trade
        let unswap_trade = UniswapUniversalTrade::new(router_trade, options).unwrap();
        let commands = unswap_trade.encode().unwrap();
        let data = build_execute_calldata(commands, 1730865534);
        assert_eq!(
            "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000672ae97e00000000000000000000000000000000000000000000000000000000000000020b080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000004563918244f4000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000008de3459add8281882cf7b05f474f6e6fcf5909f60000000000000000000000000000000000000000000000004563918244f40000000000000000000000000000000000000000000000000000000002c783af9a1a00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000576e2bed8f7b46d34016198911cdf9886f78bea7",
            hex::encode(data)
        );
    }

    #[test]
    pub fn test_v3_swap_exact_in_trump47_with_fee() {
        // https://etherscan.io/tx/0x4baa15174099e4255ce866b9cecb50b878b8aa9107fa712caf8b147037aa6e3a
        let eth = NativeBuilder::default().build().unwrap();
        let meme = Erc20TokenBuilder::default()
            .address(Address::from_str("0x535887989b9EdffB63b1Fd5C6b99a4d45443b49a").unwrap())
            .decimals(9)
            .symbol(Some("TRUMP47".to_string()))
            .name(Some("TRUMP47".to_string()))
            .build()
            .unwrap();
        let router_trade = RouterTrade::V3 {
            swaps: vec![Swap {
                input_amount: CurrencyAmount {
                    currency: CurrencyType::Native(eth.clone()),
                    amount: U256::from(10000000000000000 as u128),
                },
                output_amount: CurrencyAmount {
                    currency: CurrencyType::Token(meme.clone()),
                    amount: U256::from(0 as u128),
                },
                route: Route::V3 {
                    input: CurrencyType::Native(eth.clone()),
                    output: CurrencyType::Token(meme.clone()),
                    path: vec![
                        CurrencyType::Native(eth.clone()),
                        CurrencyType::Token(meme.clone()),
                    ],
                    fee: vec![10000],
                },
            }],
            trade_type: TradeType::ExactInput,
            input_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(10000000000000000 as u128),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Token(meme.clone()),
                amount: U256::from(5647003662877 as u128),
            },
        };
        let options = SwapOptionsBuilder::default()
            .fee(
                FeeOptionsBuilder::default()
                    .fee(25)
                    .recipient(
                        Address::from_str("0x000000fee13a103a10d593b9ae06b3e05f2e7e1c").unwrap(),
                    )
                    .build()
                    .unwrap(),
            )
            .recipient(Some(
                Address::from_str("0xBF05Cb52157777427BA9Bb6d13DFFEcb5a4374B8").unwrap(),
            ))
            .build()
            .unwrap();
        // unswap trade
        let unswap_trade = UniswapUniversalTrade::new(router_trade, options).unwrap();
        let commands = unswap_trade.encode().unwrap();
        let data = build_execute_calldata(commands, 1730871540);
        assert_eq!(
            "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000672b00f400000000000000000000000000000000000000000000000000000000000000040b000604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000002386f26fc1000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000002386f26fc10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2002710535887989b9edffb63b1fd5c6b99a4d45443b49a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000535887989b9edffb63b1fd5c6b99a4d45443b49a000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c00000000000000000000000000000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000535887989b9edffb63b1fd5c6b99a4d45443b49a000000000000000000000000bf05cb52157777427ba9bb6d13dffecb5a4374b800000000000000000000000000000000000000000000000000000522cba5ba1d",
            hex::encode(data)
        );
    }

    #[test]
    fn test_encode_decode_permit2_swap() {
        // https://etherscan.io/tx/0x498e9836d14b586ed95e9beeee3096c2a5de27df3b557c37558788c1efacc9cb
        let eth = NativeBuilder::default().build().unwrap();
        let token = Erc20TokenBuilder::default()
            .address(Address::from_str("0x535887989b9EdffB63b1Fd5C6b99a4d45443b49a").unwrap())
            .decimals(9)
            .symbol(Some("TRUMP47".to_string()))
            .name(Some("TRUMP47".to_string()))
            .build()
            .unwrap();
        let permit_parms = Permit2PermitParams {
            permit_single: PermitSingle {
                details: PermitDetails {
                    token: Address::from_str("0x535887989b9edffb63b1fd5c6b99a4d45443b49a").unwrap(),
                    amount: U256::from_str("1461501637330902918203684832716283019655932542975").unwrap(),
                    expiration: U256::from(1733580925),
                    nonce: U256::from(0),
                },
                spender: Address::from_str("0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad").unwrap(),
                sig_deadline: U256::from(1730990725),
            },
            signature: hex::decode(
                "0x18fba4c47d341d2fc89d0d106ac75e866b4e34a196168a69099ab7e96ca6fa8506984a31aa6fedfd4b41c667162d22a1c99b0535348cf66e5be48730c03c2cf11b",
            )
            .unwrap(),
        };

        //  V2 Swap
        let v2_swap = Swap {
            input_amount: CurrencyAmount {
                currency: CurrencyType::Token(token.clone()),
                amount: U256::from(11634769300000000u64),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(0u64), // 输出金额设为0
            },
            route: Route::V2 {
                input: CurrencyType::Token(token.clone()),
                output: CurrencyType::Native(eth.clone()),
                path: vec![
                    CurrencyType::Token(token.clone()),
                    CurrencyType::Native(eth.clone()),
                ],
            },
        };

        // V3 Swap
        let v3_swap = Swap {
            input_amount: CurrencyAmount {
                currency: CurrencyType::Token(token.clone()),
                amount: U256::from(4986329700000000u64),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(0u64), // 输出金额设为0
            },
            route: Route::V3 {
                input: CurrencyType::Token(token.clone()),
                output: CurrencyType::Native(eth.clone()),
                path: vec![
                    CurrencyType::Token(token.clone()),
                    CurrencyType::Native(eth.clone()),
                ],
                fee: vec![10000], // 0x2710 = 10000
            },
        };
        let router_trade = RouterTrade::Mixed {
            swaps: vec![v2_swap, v3_swap],
            trade_type: TradeType::ExactInput,
            input_amount: CurrencyAmount {
                currency: CurrencyType::Token(token.clone()),
                amount: U256::from(11634769300000000u64 as u128),
            },
            output_amount: CurrencyAmount {
                currency: CurrencyType::Native(eth.clone()),
                amount: U256::from(1429679306426672471u64), // 输出eth的数量
            },
        };
        let options = SwapOptionsBuilder::default()
            .fee(
                FeeOptionsBuilder::default()
                    .fee(25)
                    .recipient(
                        Address::from_str("0x000000fee13a103a10d593b9ae06b3e05f2e7e1c").unwrap(),
                    )
                    .build()
                    .unwrap(),
            )
            .recipient(Some(
                Address::from_str("0x24a3a6D28DdB337fb4De701406373b5c2DAfb430").unwrap(),
            ))
            .input_token_permit(permit_parms)
            .build()
            .unwrap();

        let uniswap_universal_trade = UniswapUniversalTrade::new(router_trade, options).unwrap();
        let commands = uniswap_universal_trade.encode().unwrap();
        let data = build_execute_calldata(commands, 1730990728);
        assert_eq!(
            hex::encode(data),
            "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000672cd28800000000000000000000000000000000000000000000000000000000000000050a0800060c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000046000000000000000000000000000000000000000000000000000000000000004e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000535887989b9edffb63b1fd5c6b99a4d45443b49a000000000000000000000000ffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000006754587d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fc91a3afd70395cd496c647d5a6cc9d4b2b7fad00000000000000000000000000000000000000000000000000000000672cd28500000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000004118fba4c47d341d2fc89d0d106ac75e866b4e34a196168a69099ab7e96ca6fa8506984a31aa6fedfd4b41c667162d22a1c99b0535348cf66e5be48730c03c2cf11b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000002955c2d32b8d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000535887989b9edffb63b1fd5c6b99a4d45443b49a000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000011b70a5a806100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002b535887989b9edffb63b1fd5c6b99a4d45443b49a002710c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c0000000000000000000000000000000000000000000000000000000000000019000000000000000000000000000000000000000000000000000000000000004000000000000000000000000024a3a6d28ddb337fb4de701406373b5c2dafb43000000000000000000000000000000000000000000000000013d73dc12249e557"
        );
    }

    #[test]
    fn test_decode_uniswap_universal_router_tx_2() {
        let right = "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000672cd28800000000000000000000000000000000000000000000000000000000000000050a0800060c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000046000000000000000000000000000000000000000000000000000000000000004e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000535887989b9edffb63b1fd5c6b99a4d45443b49a000000000000000000000000ffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000006754587d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fc91a3afd70395cd496c647d5a6cc9d4b2b7fad00000000000000000000000000000000000000000000000000000000672cd28500000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000004118fba4c47d341d2fc89d0d106ac75e866b4e34a196168a69099ab7e96ca6fa8506984a31aa6fedfd4b41c667162d22a1c99b0535348cf66e5be48730c03c2cf11b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000002955c2d32b8d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000535887989b9edffb63b1fd5c6b99a4d45443b49a000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000011b70a5a806100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002b535887989b9edffb63b1fd5c6b99a4d45443b49a002710c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c0000000000000000000000000000000000000000000000000000000000000019000000000000000000000000000000000000000000000000000000000000004000000000000000000000000024a3a6d28ddb337fb4de701406373b5c2dafb43000000000000000000000000000000000000000000000000013d73dc12249e557";
        let fail =  "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000672cd28800000000000000000000000000000000000000000000000000000000000000050a0800060c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000046000000000000000000000000000000000000000000000000000000000000004e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000535887989b9edffb63b1fd5c6b99a4d45443b49a000000000000000000000000ffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000006754587d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fc91a3afd70395cd496c647d5a6cc9d4b2b7fad00000000000000000000000000000000000000000000000000000000672cd28500000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000004118fba4c47d341d2fc89d0d106ac75e866b4e34a196168a69099ab7e96ca6fa8506984a31aa6fedfd4b41c667162d22a1c99b0535348cf66e5be48730c03c2cf11b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000002955c2d32b8d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000535887989b9edffb63b1fd5c6b99a4d45443b49a000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000011b70a5a806100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002b535887989b9edffb63b1fd5c6b99a4d45443b49a002710c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c0000000000000000000000000000000000000000000000000000000000000019000000000000000000000000000000000000000000000000000000000000004000000000000000000000000024a3a6d28ddb337fb4de701406373b5c2dafb43000000000000000000000000000000000000000000000000013d73dc12249e557";
        let res = execute_decode(&right);

        let res2 = execute_decode(&fail);
        println!("r {}\n\n", res.to_string());

        println!("f {}\n\n", res2.to_string());
    }
}
