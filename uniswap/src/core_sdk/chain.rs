#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainId {
    Mainnet = 1,
    Goerli = 5,
    Sepolia = 11155111,
    Optimism = 10,
    OptimismGoerli = 420,
    OptimismSepolia = 11155420,
    ArbitrumOne = 42161,
    ArbitrumGoerli = 421613,
    ArbitrumSepolia = 421614,
    Polygon = 137,
    PolygonMumbai = 80001,
    Celo = 42220,
    CeloAlfajores = 44787,
    Gnosis = 100,
    Moonbeam = 1284,
    Bnb = 56,
    Avalanche = 43114,
    BaseGoerli = 84531,
    Base = 8453,
    Zora = 7777777,
    ZoraSepolia = 999999999,
    Rootstock = 30,
    Blast = 81457,
    Zksync = 324,
    Worldchain = 480,
    AstrochainSepolia = 1301,
}

impl Into<u32> for ChainId {
    fn into(self) -> u32 {
        self as u32
    }
}
impl Into<i32> for ChainId {
    fn into(self) -> i32 {
        self as i32
    }
}

impl From<u64> for ChainId {
    fn from(chain_id: u64) -> Self {
        match chain_id {
            1 => Self::Mainnet,
            5 => Self::Goerli,
            11155111 => Self::Sepolia,
            10 => Self::Optimism,
            420 => Self::OptimismGoerli,
            11155420 => Self::OptimismSepolia,
            42161 => Self::ArbitrumOne,
            421613 => Self::ArbitrumGoerli,
            421614 => Self::ArbitrumSepolia,
            137 => Self::Polygon,
            80001 => Self::PolygonMumbai,
            42220 => Self::Celo,
            44787 => Self::CeloAlfajores,
            100 => Self::Gnosis,
            1284 => Self::Moonbeam,
            56 => Self::Bnb,
            43114 => Self::Avalanche,
            84531 => Self::BaseGoerli,
            8453 => Self::Base,
            7777777 => Self::Zora,
            999999999 => Self::ZoraSepolia,
            30 => Self::Rootstock,
            81457 => Self::Blast,
            324 => Self::Zksync,
            480 => Self::Worldchain,
            1301 => Self::AstrochainSepolia,
            _ => panic!("Unknown chain ID: {}", chain_id),
        }
    }
}
