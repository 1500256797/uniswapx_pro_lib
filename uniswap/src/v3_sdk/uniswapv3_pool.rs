use alloy::primitives::U256;

use crate::core_sdk::currency::Erc20Token;

pub enum UniswapPoolFee {
    Fee10000, // 1%
    Fee3000,  // 0.3%
    Fee500,   // 0.05%
    Fee100,   // 0.01%
}
impl UniswapPoolFee {
    pub fn as_u32(&self) -> u32 {
        match self {
            UniswapPoolFee::Fee10000 => 10000,
            UniswapPoolFee::Fee3000 => 3000,
            UniswapPoolFee::Fee500 => 500,
            UniswapPoolFee::Fee100 => 100,
        }
    }
}

// // V3 Pool 结构体
// pub struct V3Pool {
//     pub token0: Erc20Token,
//     pub token1: Erc20Token,
//     pub fee: UniswapPoolFee,
//     pub sqrt_price_x96: U256, // 当前价格的平方根 * 2^96
//     pub liquidity: U256,      // 当前流动性
//     pub tick: i32,            // 当前 tick
// }
