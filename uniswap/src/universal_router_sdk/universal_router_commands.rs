// https://docs.uniswap.org/contracts/universal-router/overview
// https://etherscan.io/address/0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad#code
use alloy::sol_types::SolCall;
use alloy::{
    dyn_abi::{abi::encode_params, DynSolType, DynSolValue},
    hex,
    primitives::{aliases::U48, Address, Bytes, U160, U256},
    sol,
    sol_types::sol_data,
};
use alloy_sol_types::{sol_data::*, SolType, SolValue};
use derive_builder::Builder;
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};
// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    UNIVERSAL_ROUTER,
    "src/abi/uniswap_universal_router.json"
);

#[derive(thiserror::Error, Debug)]
pub enum UniversalRouterError {
    #[error("当前command 暂不支持")]
    IvalidCommand,

    #[error("当前command 暂不支持{0}")]
    UnsupportCommand(u8),
}

// define the commands trait
pub trait Command {
    fn encode(&self) -> Option<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub enum UniswapV3UniversalRouterCommand {
    V3SwapExactIn(V3SwapExactInParams),
    V3SwapExactOut(V3SwapExactOutParams),
    Permit2TransferFrom(Permit2TransferFromParams),
    Permit2PermitBatch(Permit2PermitBatchParams),
    Sweep(SweepParams),
    Transfer(TransferParams),
    PayPortion(PayPortionParams),
    V2SwapExactIn(V2SwapExactInParams),
    V2SwapExactOut(V2SwapExactOutParams),
    Permit2Permit(Permit2PermitParams),
    WrapEth(WrapEthParams),
    UnwrapWeth(UnwrapWethParams),
    Permit2TransferFromBatch(Permit2TransferFromBatchParams),
    Seaport(SeaportParams),
    LooksRare721(LooksRare721Params),
    Nftx(NftxParams),
    Cryptopunks(CryptopunksParams),
    LooksRare1155(LooksRare1155Params),
    OwnerCheck721(OwnerCheck721Params),
    OwnerCheck1155(OwnerCheck1155Params),
    SweepErc721(SweepErc721Params),
    X2Y2_721(X2Y2_721Params),
    Sudoswap(SudoswapParams),
    Nft20(Nft20Params),
    X2Y2_1155(X2Y2_1155Params),
    Foundation(FoundationParams),
    SweepErc1155(SweepErc1155Params),
    ElementMarket(ElementMarketParams),
    SeaportV1_4(SeaportV1_4Params),
    ExecuteSubPlan(ExecuteSubPlanParams),
    ApproveErc20(ApproveErc20Params),
}

impl UniswapV3UniversalRouterCommand {
    pub fn decode(&self, data: &[u8]) -> std::string::String {
        match self {
            Self::V3SwapExactIn(_) => {
                // 使用 V3SwapExactInParams 的 decode 方法
                V3SwapExactInParams::print_decoded_params(data);
                "V3SwapExactIn decoded".to_string()
            }
            Self::V2SwapExactIn(_) => {
                V2SwapExactInParams::print_decoded_params(data);
                "V2SwapExactIn decoded".to_string()
            }
            Self::PayPortion(_) => {
                PayPortionParams::print_decoded_params(data);
                "PayPortion decoded".to_string()
            }
            Self::Sweep(_) => {
                SweepParams::print_decoded_params(data);
                "Sweep decoded".to_string()
            }
            Self::WrapEth(_) => {
                WrapEthParams::print_decoded_params(data);
                "WrapEth decoded".to_string()
            }
            Self::UnwrapWeth(_) => {
                UnwrapWethParams::print_decoded_params(data);
                "UnwrapWeth decoded".to_string()
            }
            Self::Permit2Permit(_) => {
                Permit2PermitParams::print_decoded_params(data);
                "Permit2Permit decoded".to_string()
            }
            _ => "Unsupported command decode".to_string(),
        }
    }
}

impl TryFrom<u8> for UniswapV3UniversalRouterCommand {
    type Error = UniversalRouterError;

    fn try_from(value: u8) -> Result<Self, UniversalRouterError> {
        match value {
            0x00 => Ok(Self::V3SwapExactIn(V3SwapExactInParams::default())),
            0x01 => Ok(Self::V3SwapExactOut(V3SwapExactOutParams::default())),
            0x02 => Ok(Self::Permit2TransferFrom(
                Permit2TransferFromParams::default(),
            )),
            0x03 => Ok(Self::Permit2PermitBatch(Permit2PermitBatchParams::default())),
            0x04 => Ok(Self::Sweep(SweepParams::default())),
            0x05 => Ok(Self::Transfer(TransferParams::default())),
            0x06 => Ok(Self::PayPortion(PayPortionParams::default())),
            0x08 => Ok(Self::V2SwapExactIn(V2SwapExactInParams::default())),
            0x09 => Ok(Self::V2SwapExactOut(V2SwapExactOutParams::default())),
            0x0a => Ok(Self::Permit2Permit(Permit2PermitParams::default())),
            0x0b => Ok(Self::WrapEth(WrapEthParams::default())),
            0x0c => Ok(Self::UnwrapWeth(UnwrapWethParams::default())),
            0x0d => Ok(Self::Permit2TransferFromBatch(
                Permit2TransferFromBatchParams::default(),
            )),
            0x10 => Ok(Self::Seaport(SeaportParams::default())),
            0x11 => Ok(Self::LooksRare721(LooksRare721Params::default())),
            0x12 => Ok(Self::Nftx(NftxParams::default())),
            0x13 => Ok(Self::Cryptopunks(CryptopunksParams::default())),
            0x14 => Ok(Self::LooksRare1155(LooksRare1155Params::default())),
            0x15 => Ok(Self::OwnerCheck721(OwnerCheck721Params::default())),
            0x16 => Ok(Self::OwnerCheck1155(OwnerCheck1155Params::default())),
            0x17 => Ok(Self::SweepErc721(SweepErc721Params::default())),
            0x18 => Ok(Self::X2Y2_721(X2Y2_721Params::default())),

            _ => Err(UniversalRouterError::UnsupportCommand(value)),
        }
    }
}

impl TryInto<u8> for UniswapV3UniversalRouterCommand {
    type Error = UniversalRouterError;
    fn try_into(self) -> Result<u8, UniversalRouterError> {
        match self {
            // 0x00 │  V3_SWAP_EXACT_IN
            Self::V3SwapExactIn(_) => Ok(0x00),
            // 0x01 │  V3_SWAP_EXACT_OUT
            Self::V3SwapExactOut(_) => Ok(0x01),
            // 0x02 │  PERMIT2_TRANSFER_FROM
            Self::Permit2TransferFrom(_) => Ok(0x02),
            // 0x03 │  PERMIT2_PERMIT_BATCH
            Self::Permit2PermitBatch(_) => Ok(0x03),
            // 0x04 │  SWEEP
            Self::Sweep(_) => Ok(0x04),
            // 0x05 │  TRANSFER
            Self::Transfer(_) => Ok(0x05),
            // 0x06 │  PAY_PORTION
            Self::PayPortion(_) => Ok(0x06),
            // 0x08 │  V2_SWAP_EXACT_IN
            Self::V2SwapExactIn(_) => Ok(0x08),
            // 0x09 │  V2_SWAP_EXACT_OUT
            Self::V2SwapExactOut(_) => Ok(0x09),
            // 0x0a │  PERMIT2_PERMIT
            Self::Permit2Permit(_) => Ok(0x0a),
            // 0x0b │  WRAP_ETH
            Self::WrapEth(_) => Ok(0x0b),
            // 0x0c │  UNWRAP_WETH
            Self::UnwrapWeth(_) => Ok(0x0c),
            // 0x0d │  PERMIT2_TRANSFER_FROM_BATCH
            Self::Permit2TransferFromBatch(_) => Ok(0x0d),
            // 0x10 │  SEAPORT_V1_5
            Self::Seaport(_) => Ok(0x10),
            // 0x11 │  LOOKS_RARE_721
            Self::LooksRare721(_) => Ok(0x11),
            // 0x12 │  NFTX
            Self::Nftx(_) => Ok(0x12),
            // 0x13 │  CRYPTOPUNKS
            Self::Cryptopunks(_) => Ok(0x13),
            // 0x14 │  LOOKS_RARE_1155
            Self::LooksRare1155(_) => Ok(0x14),
            // 0x15 │  OWNER_CHECK_721
            Self::OwnerCheck721(_) => Ok(0x15),
            // 0x16 │  OWNER_CHECK_1155
            Self::OwnerCheck1155(_) => Ok(0x16),
            // 0x17 │  SWEEP_ERC721
            Self::SweepErc721(_) => Ok(0x17),
            // 0x18 │  X2Y2_721
            Self::X2Y2_721(_) => Ok(0x18),
            // 0x19 │  SUDOSWAP
            Self::Sudoswap(_) => Ok(0x19),
            // 0x1a │  NFT20
            Self::Nft20(_) => Ok(0x1a),
            // 0x1b │  X2Y2_1155
            Self::X2Y2_1155(_) => Ok(0x1b),
            // 0x1c │  FOUNDATION
            Self::Foundation(_) => Ok(0x1c),
            // 0x1d │  SWEEP_ERC1155
            Self::SweepErc1155(_) => Ok(0x1d),
            // 0x1e │  ELEMENT_MARKET
            Self::ElementMarket(_) => Ok(0x1e),
            // 0x20 │  SEAPORT_V1_4
            Self::SeaportV1_4(_) => Ok(0x20),
            // 0x21 │  EXECUTE_SUB_PLAN
            Self::ExecuteSubPlan(_) => Ok(0x21),
            // 0x22 │  APPROVE_ERC20
            Self::ApproveErc20(_) => Ok(0x22),
        }
    }
}

impl Command for UniswapV3UniversalRouterCommand {
    fn encode(&self) -> Option<Vec<u8>> {
        match self {
            Self::V3SwapExactIn(params) => Some(params.encode()),
            Self::V3SwapExactOut(params) => Some(params.encode()),
            Self::Sweep(params) => Some(params.encode()),
            Self::PayPortion(params) => Some(params.encode()),
            Self::V2SwapExactIn(params) => Some(params.encode()),
            Self::V2SwapExactOut(params) => Some(params.encode()),
            Self::Permit2Permit(params) => Some(params.encode()),
            Self::WrapEth(params) => Some(params.encode()),
            Self::UnwrapWeth(params) => Some(params.encode()),
            Self::Permit2TransferFromBatch(params) => Some(params.encode()),
            Self::Seaport(params) => Some(params.encode()),
            Self::LooksRare721(params) => Some(params.encode()),
            Self::Nftx(params) => Some(params.encode()),
            Self::Cryptopunks(params) => Some(params.encode()),
            Self::LooksRare1155(params) => Some(params.encode()),
            _ => None,
        }
    }
}

#[derive(Builder, Default, Debug, Clone)]
pub struct V3SwapExactInParams {
    /// The recipient of the output of the trade
    pub recipient: Address,
    /// The amount of input tokens for the trade  
    pub amount_in: U256,
    /// The minimum amount of output tokens the user wants
    pub min_amount_out: U256,
    /// The UniswapV3 encoded path to trade along
    pub path: Vec<u8>,
    /// A flag for whether the input tokens should come from the msg.sender (through Permit2) or whether the funds are already in the UniversalRouter
    pub use_permit2: bool,
}

impl V3SwapExactInParams {
    pub fn encode(&self) -> Vec<u8> {
        sol!(
            #[allow(missing_docs)]
            function v3SwapExactIn(
                address recipient,
                uint256 amountIn,
                uint256 amountOutMin,
                bytes calldata path,
                bool usePermit2
            ) external returns (uint256 amountOut);
        );

        // address The recipient of the output of the trade
        // uint256 The amount of input tokens for the trade
        // uint256 The minimum amount of output tokens the user wants
        // bytes The UniswapV3 encoded path to trade along
        // bool A flag for whether the input tokens should come from the msg.sender (through Permit2) or whether the funds are already in the UniversalRouter
        let swap_data = v3SwapExactInCall::new((
            self.recipient,
            self.amount_in,
            self.min_amount_out,
            self.path.clone().into(),
            self.use_permit2,
        ));

        let encode = v3SwapExactInCall::abi_encode(&swap_data);
        // trim the first 4 bytes
        encode[4..].to_vec()
    }

    pub fn print_decoded_params(data: &[u8]) {
        sol!(
            #[allow(missing_docs)]
            function v3SwapExactIn(address recipient, uint256 amountIn, uint256 amountOutMin, bytes calldata path, bool usePermit2) external returns (uint256 amountOut);
        );
        // generate selector
        let mut hasher = Keccak::v256();
        hasher.update(b"v3SwapExactIn(address,uint256,uint256,bytes,bool)");
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        let selector = &result[0..4];
        let mut new_data = selector.to_vec();
        new_data.extend_from_slice(data);
        let decoded = v3SwapExactInCall::abi_decode(&new_data, false).unwrap();
        println!(
            "v3SwapExactInCall: {:?}, {:?}, {:?}, {:?}, {:?}",
            decoded.recipient,
            decoded.amountIn,
            decoded.amountOutMin,
            decoded.path,
            decoded.usePermit2
        );
    }
}

#[derive(Debug, Default, Clone, Builder)]
pub struct V3SwapExactOutParams {
    /// The recipient of the output of the trade
    pub recipient: Address,
    /// The amount of output tokens to receive
    pub amount_out: U256,
    /// The maximum number of input tokens that should be spent
    pub max_amount_in: U256,
    /// The UniswapV3 encoded path to trade along  
    pub path: Vec<u8>,
    /// A flag for whether the input tokens should come from the msg.sender (through Permit2) or whether the funds are already in the UniversalRouter
    pub use_permit2: bool,
}

impl V3SwapExactOutParams {
    pub fn as_command(&self) -> u8 {
        0x01
    }
    // address The recipient of the output of the trade
    // uint256 The amount of output tokens to receive
    // uint256 The maximum number of input tokens that should be spent
    // bytes The UniswapV3 encoded path to trade along
    // bool A flag for whether the input tokens should come from the msg.sender (through Permit2) or whether the funds are already in the UniversalRouter
    pub fn encode(&self) -> Vec<u8> {
        let data = DynSolValue::Tuple(vec![
            DynSolValue::Address(self.recipient),
            DynSolValue::Uint(self.amount_out, 256),
            DynSolValue::Uint(self.max_amount_in, 256),
            DynSolValue::Bytes(self.path.clone()),
            DynSolValue::Bool(self.use_permit2),
        ]);
        data.abi_encode()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Permit2TransferFromParams {
    /// The token to fetch from Permit2
    pub token: Address,
    /// The recipient of the tokens fetched  
    pub recipient: Address,
    /// The amount of token to fetch
    pub amount: U256,
}

#[derive(Debug, Clone, Default)]
pub struct Permit2PermitBatchParams {
    /// A PermitBatch struct outlining all of the Permit2 permits to execute.
    pub permit_batch: Bytes,
    /// The signature to provide to Permit2
    pub signature: Bytes,
}

#[derive(Debug, Clone, Default, Builder)]
pub struct SweepParams {
    /// The ERC20 token to sweep (or Constants.ETH for ETH)
    pub token: Address,
    /// The recipient of the sweep
    pub recipient: Address,
    /// The minimum required tokens to receive from the sweep  
    pub min_amount_out: U256,
}

impl SweepParams {
    pub fn as_command(&self) -> u8 {
        0x04
    }
    pub fn encode(&self) -> Vec<u8> {
        // address The ERC20 token to sweep (or Constants.ETH for ETH)
        // address The recipient of the sweep
        // uint256 The minimum required tokens to receive from the sweep
        sol!(
            #[allow(missing_docs)]
            function sweep(address token, address recipient, uint256 minAmountOut) external returns (uint256 amountOut);
        );
        let sweep_data = sweepCall::new((self.token, self.recipient, self.min_amount_out));
        sweepCall::abi_encode(&sweep_data)[4..].to_vec()
    }

    pub fn print_decoded_params(data: &[u8]) {
        sol!(
            #[allow(missing_docs)]
            function sweep(address token, address recipient, uint256 minAmountOut) external returns (uint256 amountOut);
        );
        // generate selector
        let mut hasher = Keccak::v256();
        hasher.update(b"sweep(address,address,uint256)");
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        let selector = &result[0..4];
        let mut new_data = selector.to_vec();
        new_data.extend_from_slice(data);
        let decoded = sweepCall::abi_decode(&new_data, false).unwrap();
        println!(
            "sweepCall: {:?}, {:?}, {:?}",
            decoded.token, decoded.recipient, decoded.minAmountOut
        );
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransferParams {
    /// The ERC20 token to transfer (or Constants.ETH for ETH)
    pub token: Address,
    /// The recipient of the transfer
    pub recipient: Address,
    /// The amount to transfer
    pub amount: U256,
}

#[derive(Debug, Clone, Default, Builder)]
pub struct PayPortionParams {
    /// The ERC20 token to transfer (or Constants.ETH for ETH)
    pub token: Address,
    /// The recipient of the transfer
    pub recipient: Address,
    /// In basis points, the percentage of the contract's balance to transfer
    pub basis_points: U256,
}

impl PayPortionParams {
    pub fn as_command(&self) -> u8 {
        0x05
    }
    // address The ERC20 token to transfer (or Constants.ETH for ETH)
    // address The recipient of the transfer
    // uint256 In basis points, the percentage of the contract’s balance to transfer

    pub fn encode(&self) -> Vec<u8> {
        sol!(
            #[allow(missing_docs)]
            function payPortion(
                address token,
                address recipient,
                uint256 basisPoints
            ) external returns (uint256 amountOut);
        );

        let swap_data = payPortionCall::new((self.token, self.recipient, self.basis_points));

        let encode = payPortionCall::abi_encode(&swap_data);
        // trim the first 4 bytes
        encode[4..].to_vec()
    }

    pub fn print_decoded_params(data: &[u8]) {
        sol!(
            #[allow(missing_docs)]
            function payPortion(
                address token,
                address recipient,
                uint256 basisPoints
            ) external returns (uint256 amountOut);
        );
        let mut hasher = Keccak::v256();
        hasher.update(b"payPortion(address,address,uint256)");
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);

        let selector = &result[0..4];
        // add selector to the front of the data
        let mut new_data = selector.to_vec();
        new_data.extend_from_slice(data);
        let decoded = payPortionCall::abi_decode(&new_data, false).unwrap();
        println!(
            "payPortionCall: {:?}, {:?}, {:?}",
            decoded.token, decoded.recipient, decoded.basisPoints
        );
    }
}
#[derive(Debug, Clone, Default, Builder)]
pub struct V2SwapExactInParams {
    /// The recipient of the output of the trade
    /// default: 0x0000000000000000000000000000000000000002
    #[builder(
        default = "Address::from_str(\"0x0000000000000000000000000000000000000002\").unwrap()"
    )]
    pub recipient: Address,
    /// The amount of input tokens for the trade
    pub amount_in: U256,
    /// The minimum amount of output tokens the user wants  
    pub min_amount_out: U256,
    /// The UniswapV2 token path to trade along
    pub path: Vec<Address>,
    /// A flag for whether the input tokens should come from the msg.sender (through Permit2) or whether the funds are already in the UniversalRouter
    #[builder(default = "false")]
    pub use_permit2: bool,
}

impl V2SwapExactInParams {
    pub fn encode(&self) -> Vec<u8> {
        // address The recipient of the output of the trade
        // uint256 The amount of input tokens for the trade
        // uint256 The minimum amount of output tokens the user wants
        // address[] The UniswapV2 token path to trade along
        // bool A flag for whether the input tokens should come from the msg.sender (through Permit2) or whether the funds are already in the UniversalRouter
        sol!(
            #[allow(missing_docs)]
            function v2SwapExactIn(address recipient, uint256 amountIn, uint256 amountOutMin, address[] calldata path, bool usePermit2) external returns (uint256 amountOut);
        );
        let data = v2SwapExactInCall::new((
            self.recipient,
            self.amount_in,
            self.min_amount_out,
            self.path.clone().into(),
            self.use_permit2,
        ));
        v2SwapExactInCall::abi_encode(&data)[4..].to_vec()
    }

    pub fn print_decoded_params(data: &[u8]) {
        sol!(
            #[allow(missing_docs)]
            function v2SwapExactIn(address recipient, uint256 amountIn, uint256 amountOutMin, address[] calldata path, bool usePermit2) external returns (uint256 amountOut);
        );
        let mut hasher = Keccak::v256();
        hasher.update(b"v2SwapExactIn(address,uint256,uint256,address[],bool)");
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        let selector = &result[0..4];
        let mut new_data = selector.to_vec();
        new_data.extend_from_slice(data);
        let decoded = v2SwapExactInCall::abi_decode(&new_data, false).unwrap();
        println!(
            "v2SwapExactInCall: {:?}, {:?}, {:?}, {:?}, {:?}",
            decoded.recipient,
            decoded.amountIn,
            decoded.amountOutMin,
            decoded.path,
            decoded.usePermit2
        );
    }
}
#[derive(Debug, Clone, Default)]
pub struct V2SwapExactOutParams {
    /// The recipient of the output of the trade
    pub recipient: Address,
    /// The amount of output tokens to receive
    pub amount_out: U256,
    /// The maximum number of input tokens that should be spent
    pub max_amount_in: U256,
    /// The UniswapV2 token path to trade along
    pub path: Vec<Address>,
    /// A flag for whether the input tokens should come from the msg.sender (through Permit2) or whether the funds are already in the UniversalRouter  
    pub use_permit2: bool,
}

impl V2SwapExactOutParams {
    pub fn encode(&self) -> Vec<u8> {
        sol!(
            #[allow(missing_docs)]
            function v2SwapExactOut(address recipient, uint256 amountOut, uint256 amountInMax, address[] calldata path, bool usePermit2) external returns (uint256 amountIn);
        );
        let data = v2SwapExactOutCall::new((
            self.recipient,
            self.amount_out,
            self.max_amount_in,
            self.path.clone().into(),
            self.use_permit2,
        ));
        v2SwapExactOutCall::abi_encode(&data)[4..].to_vec()
    }
}
#[derive(Debug, Clone, Default)]
pub struct PermitDetails {
    /// ERC20 token address
    pub token: Address,
    /// the maximum amount allowed to spend
    pub amount: U256,
    /// timestamp at which a spender's token allowances become invalid
    pub expiration: U256,
    /// an incrementing value indexed per owner,token,and spender for each signature
    pub nonce: U256,
}
#[derive(Debug, Clone, Default)]
pub struct PermitSingle {
    /// the permit data for a single token alownce
    pub details: PermitDetails,
    /// address permissioned on the allowed tokens
    pub spender: Address,
    /// deadline on the permit signature
    pub sig_deadline: U256,
}
#[derive(Debug, Clone, Default)]
pub struct Permit2PermitParams {
    /// A PermitSingle struct outlining the Permit2 permit to execute
    pub permit_single: PermitSingle,
    /// The signature to provide to Permit2
    pub signature: Vec<u8>,
}

impl Permit2PermitParams {
    pub fn encode(&self) -> Vec<u8> {
        sol!(
            #[allow(missing_docs)]
            struct PermitDetails {
                address token;
                uint256 amount;
                uint256 expiration;
                uint256 nonce;
            }

            #[allow(missing_docs)]
            struct PermitSingle {
                PermitDetails details;
                address spender;
                uint256 sigDeadline;
            }

            #[allow(missing_docs)]
            function permit2Permit(PermitSingle memory permitSingle, bytes memory signature) external returns (bytes4);
        );
        let permit_details = PermitDetails {
            token: self.permit_single.details.token,
            amount: self.permit_single.details.amount,
            expiration: self.permit_single.details.expiration,
            nonce: self.permit_single.details.nonce,
        };
        let permit_single = PermitSingle {
            details: permit_details,
            spender: self.permit_single.spender,
            sigDeadline: self.permit_single.sig_deadline,
        };
        let permit_2_permit =
            permit2PermitCall::new((permit_single, self.signature.clone().into()));
        permit_2_permit.abi_encode()[4..].to_vec()
    }

    pub fn print_decoded_params(data: &[u8]) {
        sol!(

            #[allow(missing_docs)]
            struct PermitDetails {
                address token;
                uint256 amount;
                uint256 expiration;
                uint256 nonce;
            }

            #[allow(missing_docs)]
            struct PermitSingle {
                PermitDetails details;
                address spender;
                uint256 sigDeadline;
            }
            #[allow(missing_docs)]
            function permit2Permit(PermitSingle memory permitSingle, bytes memory signature) external returns (bytes4);
        );
        let mut hasher = Keccak::v256();
        hasher.update(b"permit2Permit(((address,uint256,uint256,uint256),address,uint256),bytes)");
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        let selector = &result[0..4];
        let mut new_data = selector.to_vec();
        new_data.extend_from_slice(data);
        let decoded = permit2PermitCall::abi_decode(&new_data, false).unwrap();
        println!(
            "permitDetails: {:?}, {:?}, {:?}, {:?}",
            decoded.permitSingle.details.token,
            decoded.permitSingle.details.amount,
            decoded.permitSingle.details.expiration,
            decoded.permitSingle.details.nonce
        );
        println!(
            "permitSingle: {:?}, {:?}",
            decoded.permitSingle.spender, decoded.permitSingle.sigDeadline
        );
        println!("signature: {:?}", decoded.signature);
    }
}
#[derive(Debug, Clone, Default, Builder)]
pub struct WrapEthParams {
    /// The recipient of the WETH
    /// default: 0x0000000000000000000000000000000000000002
    #[builder(
        default = "Address::from_str(\"0x0000000000000000000000000000000000000002\").unwrap()"
    )]
    pub recipient: Address,
    /// The amount of ETH to wrap
    pub amount: U256,
}

impl WrapEthParams {
    pub fn encode(&self) -> Vec<u8> {
        sol!(
            #[allow(missing_docs)]
            function wrapEth(address recipient, uint256 amount) external returns (uint256 amountOut);
        );
        let data = wrapEthCall::new((self.recipient, self.amount));
        wrapEthCall::abi_encode(&data)[4..].to_vec()
    }

    pub fn print_decoded_params(data: &[u8]) {
        sol!(
            #[allow(missing_docs)]
            function wrapEth(address recipient, uint256 amount) external returns (uint256 amountOut);
        );
        let mut hasher = Keccak::v256();
        hasher.update(b"wrapEth(address,uint256)");
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        let selector = &result[0..4];
        let mut new_data = selector.to_vec();
        new_data.extend_from_slice(data);
        let decoded = wrapEthCall::abi_decode(&new_data, false).unwrap();
        println!("wrapEthCall: {:?}, {:?}", decoded.recipient, decoded.amount);
    }
}
#[derive(Debug, Clone, Default)]
pub struct UnwrapWethParams {
    /// The recipient of the ETH  
    pub recipient: Address,
    /// The minimum required ETH to receive from the unwrapping
    pub min_amount_out: U256,
}

impl UnwrapWethParams {
    pub fn encode(&self) -> Vec<u8> {
        sol!(
            #[allow(missing_docs)]
            function unwrapWeth(address recipient, uint256 minAmountOut) external returns (uint256 amountOut);
        );
        let data = unwrapWethCall::new((self.recipient, self.min_amount_out));
        unwrapWethCall::abi_encode(&data)[4..].to_vec()
    }

    pub fn print_decoded_params(data: &[u8]) {
        sol!(
            #[allow(missing_docs)]
            function unwrapWeth(address recipient, uint256 minAmountOut) external returns (uint256 amountOut);
        );
        let mut hasher = Keccak::v256();
        hasher.update(b"unwrapWeth(address,uint256)");
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        let selector = &result[0..4];
        let mut new_data = selector.to_vec();
        new_data.extend_from_slice(data);
        let decoded = unwrapWethCall::abi_decode(&new_data, false).unwrap();
        println!(
            "unwrapWethCall: {:?}, {:?}",
            decoded.recipient, decoded.minAmountOut
        );
    }
}
#[derive(Debug, Clone, Default)]
pub struct Permit2TransferFromBatchParams {
    /// An array of AllowanceTransferDetails structs that each describe a Permit2 transfer to perform
    pub transfers: Vec<Bytes>,
}

impl Permit2TransferFromBatchParams {
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }
}
#[derive(Debug, Clone, Default)]
pub struct SeaportParams {
    /// The ETH value to forward to the Seaport contract
    pub value: U256,
    /// The calldata to use to call the Seaport contract  
    pub calldata: Bytes,
}

impl SeaportParams {
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }
}
#[derive(Debug, Clone, Default)]
pub struct LooksRare721Params {
    /// The ETH value to forward to the LooksRare contract
    pub value: U256,
    /// The calldata to use to call the LooksRare contract
    pub calldata: Bytes,
    /// The recipient of the ERC721
    pub recipient: Address,
    /// The ERC721 token address
    pub token: Address,
    /// The ID of the ERC721
    pub token_id: U256,
}

impl LooksRare721Params {
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }
}
#[derive(Debug, Clone, Default)]
pub struct NftxParams {
    /// The ETH value to forward to the NFTX contract
    pub value: U256,
    /// The calldata to use to call the NFTX contract
    pub calldata: Bytes,
}

impl NftxParams {
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }
}
#[derive(Debug, Clone, Default)]
pub struct CryptopunksParams {
    /// The PunkID to purchase
    pub punk_id: U256,
    /// The recipient for the cryptopunk
    pub recipient: Address,
    /// The ETH value to forward to the Cryptopunks contract
    pub value: U256,
}

impl CryptopunksParams {
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }
}
#[derive(Debug, Clone, Default)]
pub struct LooksRare1155Params {
    /// The ETH value to forward to the LooksRare contract
    pub value: U256,
    /// The calldata to use to call the LooksRare contract
    pub calldata: Bytes,
    /// The recipient of the ERC1155
    pub recipient: Address,
    /// The ERC1155 token address
    pub token: Address,
    /// The ID of the ERC1155
    pub token_id: U256,
    /// The amount of the ERC1155 to transfer
    pub amount: U256,
}

impl LooksRare1155Params {
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }
}
#[derive(Debug, Clone, Default)]
pub struct OwnerCheck721Params {
    /// The required owner of the ERC721
    pub owner: Address,
    /// The ERC721 token address
    pub token: Address,
    /// The ID of the ERC721
    pub token_id: U256,
}
#[derive(Debug, Clone, Default)]
pub struct OwnerCheck1155Params {
    /// The required owner of the ERC1155
    pub owner: Address,
    /// The ERC721 token address
    pub token: Address,
    /// The ID of the ERC1155
    pub token_id: U256,
    /// The minimum required amount of the ERC1155
    pub min_amount: U256,
}
#[derive(Debug, Clone, Default)]
pub struct SweepErc721Params {
    /// The ERC721 token address to transfer
    pub token: Address,
    /// The recipient of the transfer
    pub recipient: Address,
    /// The token ID to transfer
    pub token_id: U256,
}
#[derive(Debug, Clone, Default)]
pub struct X2Y2_721Params {
    /// The ETH value to forward to the X2Y2 contract
    pub value: U256,
    /// The calldata to use to call the X2Y2 contract
    pub calldata: Bytes,
    /// The recipient of the ERC721
    pub recipient: Address,
    /// The ERC721 token address
    pub token: Address,
    /// The ID of the ERC721
    pub token_id: U256,
}
#[derive(Debug, Clone, Default)]
pub struct SudoswapParams {
    /// The ETH value to forward to the Sudoswap contract
    pub value: U256,
    /// The calldata to use to call the Sudoswap contract
    pub calldata: Bytes,
}
#[derive(Debug, Clone, Default)]
pub struct Nft20Params {
    /// The ETH value to forward to the NFT20 contract
    pub value: U256,
    /// The calldata to use to call the NFT20 contract
    pub calldata: Bytes,
}
#[derive(Debug, Clone, Default)]
pub struct X2Y2_1155Params {
    /// The ETH value to forward to the X2Y2 contract
    pub value: U256,
    /// The calldata to use to call the X2Y2 contract
    pub calldata: Bytes,
    /// The recipient of the ERC1155
    pub recipient: Address,
    /// The ERC1155 token address
    pub token: Address,
    /// The ID of the ERC1155
    pub token_id: U256,
    /// The amount of the ERC1155 to transfer
    pub amount: U256,
}
#[derive(Debug, Clone, Default)]
pub struct FoundationParams {
    /// The ETH value to forward to the Foundation contract
    pub value: U256,
    /// The calldata to use to call the Foundation contract
    pub calldata: Bytes,
    /// The recipient of the ERC721
    pub recipient: Address,
    /// The ERC721 token address
    pub token: Address,
    /// The ID of the ERC721
    pub token_id: U256,
}
#[derive(Debug, Clone, Default)]
pub struct SweepErc1155Params {
    /// The ERC1155 token address to sweep
    pub token: Address,
    /// The recipient of the sweep
    pub recipient: Address,
    /// The token ID to sweep
    pub token_id: U256,
    /// The minimum required tokens to receive from the sweep
    pub min_amount_out: U256,
}
#[derive(Debug, Clone, Default)]
pub struct ElementMarketParams {
    // Element Market 命令参数
}
#[derive(Debug, Clone, Default)]
pub struct SeaportV1_4Params {
    // Seaport V1.4 命令参数
}
#[derive(Debug, Clone, Default)]
pub struct ExecuteSubPlanParams {
    // Execute Sub Plan 命令参数
}
#[derive(Debug, Clone, Default)]
pub struct ApproveErc20Params {
    // Approve ERC20 命令参数
}

pub fn encode_path(path: &[Address], fees: &[u32]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&path[0].0 .0);
    for i in 0..fees.len() {
        encoded.extend_from_slice(&fees[i].to_be_bytes()[1..4]);
        encoded.extend_from_slice(&path[i + 1].0 .0);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use alloy::primitives::utils::parse_units;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_encode_v3_swap_exact_in() {
        // https://etherscan.io/tx/0x2499768d1cef7635c9c14608e1f36f2990175b2ad28c070e6f0a6e8e466b50d0
        let usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        let usdc_amount_in = parse_units("500.0", 6).unwrap();
        let meme = "0xCb76314C2540199f4B844D4ebbC7998C604880cA";
        // https://uniswapv3book.com/milestone_4/path.html
        let path = encode_path(
            &[
                usdt.parse().unwrap(),
                weth.parse().unwrap(),
                meme.parse().unwrap(),
            ],
            &[100, 10000],
        );
        assert_eq!(
            "dac17f958d2ee523a2206206994597c13d831ec7000064c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2002710cb76314c2540199f4b844d4ebbc7998c604880ca",
            hex::encode(path.clone())
        );
        let params = V3SwapExactInParams {
            recipient: Address::from_str("0x0000000000000000000000000000000000000002").unwrap(),
            amount_in: usdc_amount_in.into(),
            min_amount_out: U256::from(0),
            path,
            use_permit2: true,
        };
        let encode_command = params.encode();
        let expected= "0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000001dcd6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000042dac17f958d2ee523a2206206994597c13d831ec7000064c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2002710cb76314c2540199f4b844d4ebbc7998c604880ca000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(expected, hex::encode(encode_command))
    }

    #[test]
    fn test_encode_decode_pay_portion() {
        // https://etherscan.io/tx/0x2499768d1cef7635c9c14608e1f36f2990175b2ad28c070e6f0a6e8e466b50d0
        let encoded_data = "000000000000000000000000cb76314c2540199f4b844d4ebbc7998c604880ca000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c0000000000000000000000000000000000000000000000000000000000000019";
        PayPortionParams::print_decoded_params(&hex::decode(encoded_data).unwrap());

        let params = PayPortionParams {
            token: Address::from_str("0xcb76314c2540199f4b844d4ebbc7998c604880ca").unwrap(),
            recipient: Address::from_str("0x000000fee13a103a10d593b9ae06b3e05f2e7e1c").unwrap(),
            basis_points: U256::from(25),
        };
        let encode = params.encode();
        assert_eq!(encoded_data, hex::encode(encode));
    }

    #[test]
    fn test_encode_decode_sweep() {
        // https://etherscan.io/tx/0x2499768d1cef7635c9c14608e1f36f2990175b2ad28c070e6f0a6e8e466b50d0
        let encoded_data = "000000000000000000000000cb76314c2540199f4b844d4ebbc7998c604880ca000000000000000000000000e62e213afd9e72efce89013c988e9008f99d7b3d00000000000000000000000000000000000000000000010e40f45acbc3d3bef2";
        SweepParams::print_decoded_params(&hex::decode(encoded_data).unwrap());

        let params = SweepParams {
            token: Address::from_str("0xcb76314c2540199f4b844d4ebbc7998c604880ca").unwrap(),
            recipient: Address::from_str("0xe62e213afd9e72efce89013c988e9008f99d7b3d").unwrap(),
            min_amount_out: U256::from(4985301365645534019314i128),
        };
        let encode = params.encode();
        assert_eq!(encoded_data, hex::encode(encode));
    }

    #[test]
    fn test_decode_uniswapv3_exact_in() {
        sol!(
            #[allow(missing_docs)]
            function v3SwapExactIn(
                address recipient,
                uint256 amountIn,
                uint256 amountOutMin,
                bytes calldata path,
                bool usePermit2
            ) external returns (uint256 amountOut);
        );
        let data = "0x5a58ec2d0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000001dcd6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000042dac17f958d2ee523a2206206994597c13d831ec7000064c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2002710cb76314c2540199f4b844d4ebbc7998c604880ca000000000000000000000000000000000000000000000000000000000000";

        let decode: Vec<u8> = hex::decode(data).unwrap();
        let res = v3SwapExactInCall::abi_decode(&decode, false).unwrap();
        println!("recipient: {:?}", res.recipient);
        println!("amountIn: {:?}", res.amountIn);
        println!("amountOutMin: {:?}", res.amountOutMin);
        println!("path: {:?}", res.path);
        println!("usePermit2: {:?}", res.usePermit2);
    }

    #[test]
    fn test_decode_uniswapv3_exact_in_eg2() {
        sol!(
            #[allow(missing_docs)]
            function swapExactTokensForTokens(
                uint256 amountIn,
                uint256 amountOutMin,
                address[] calldata path,
                address to,
                uint256 deadline
              ) external returns (uint256[] memory amounts);
        );
        let input = "0x38ed173900000000000000000000000000000000000000000001a717cc0a3e4f84c00000000000000000000000000000000000000000000000000000000000000283568400000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000201f129111c60401630932d9f9811bd5b5fff34e000000000000000000000000000000000000000000000000000000006227723d000000000000000000000000000000000000000000000000000000000000000200000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7";
        let input = hex::decode(input).unwrap();
        // Decode the input using the generated `swapExactTokensForTokens` bindings.
        let decoded = swapExactTokensForTokensCall::abi_decode(&input, false);
        match decoded {
            Ok(decoded) => {
                let path = decoded.path;

                println!(
                    "Swap {} of token {} to {} of token {}",
                    decoded.amountIn,
                    path.first().expect("Path is empty"),
                    decoded.amountOutMin,
                    path.last().expect("Path is empty")
                );
            }
            Err(e) => {
                println!("Error decoding input: {e:?}");
            }
        }
        ();
    }

    #[test]
    fn test_gen_method_sig() {
        use tiny_keccak::{Hasher, Keccak};

        let mut hasher = Keccak::v256();
        hasher.update(b"v3SwapExactIn(address,uint256,uint256,bytes,bool)");
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);

        let selector = &result[0..4];
        println!("Function selector: 0x{}", hex::encode(selector));
    }

    #[test]
    fn test_entire_tx() {
        // https://etherscan.io/tx/0xf22ab28d47e8aaa37d54dbf3836c1bc1f1560b373be7466bea2bd669c0670258
        // 0x0b080604
        {
            // 0x0b: WRAP_ETH
            let data = "00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000429d069189e0000";
            WrapEthParams::print_decoded_params(&hex::decode(data).unwrap());
            let encode = WrapEthParams {
                recipient: Address::from_str("0x0000000000000000000000000000000000000002").unwrap(),
                amount: U256::from(300000000000000000i128),
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
        {
            // 0x08: V2_SWAP_EXACT_IN
            let data = "00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000429d069189e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000b612bfc5ce2fb1337bd29f5af24ca85dbb181ce2";
            V2SwapExactInParams::print_decoded_params(&hex::decode(data).unwrap());
            let encode = V2SwapExactInParams {
                recipient: Address::from_str("0x0000000000000000000000000000000000000002").unwrap(),
                amount_in: U256::from(300000000000000000i128),
                min_amount_out: U256::from(0),
                path: vec![
                    Address::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                    Address::from_str("0xb612bfc5ce2fb1337bd29f5af24ca85dbb181ce2").unwrap(),
                ],
                use_permit2: false,
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
        {
            // 0x06: PAY_PORTION
            let data = "000000000000000000000000b612bfc5ce2fb1337bd29f5af24ca85dbb181ce2000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c0000000000000000000000000000000000000000000000000000000000000019";
            PayPortionParams::print_decoded_params(&hex::decode(data).unwrap());
            let encode = PayPortionParams {
                token: Address::from_str("0xb612bfc5ce2fb1337bd29f5af24ca85dbb181ce2").unwrap(),
                recipient: Address::from_str("0x000000fee13a103a10d593b9ae06b3e05f2e7e1c").unwrap(),
                basis_points: U256::from(25),
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
        {
            // 0x04: SWEEP
            let data = "000000000000000000000000b612bfc5ce2fb1337bd29f5af24ca85dbb181ce20000000000000000000000007d829bab617e659a5b4fbd8fd9fbaffa1ed9839e00000000000000000000000000000000000000000000000000002156c41d8dd3";
            SweepParams::print_decoded_params(&hex::decode(data).unwrap());
            let encode = SweepParams {
                token: Address::from_str("0xb612bfc5ce2fb1337bd29f5af24ca85dbb181ce2").unwrap(),
                recipient: Address::from_str("0x7d829bab617e659a5b4fbd8fd9fbaffa1ed9839e").unwrap(),
                min_amount_out: U256::from(36656541175251u128),
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
    }

    #[test]
    fn test_encode_decode_v2_swap_exact_in() {
        // https://etherscan.io/tx/0x06ca44dbd8ff6cd4989a378009c4422a732739e9c3d4e807d0201366052380f5
        // 0x0b08
        {
            // 0x0b: WRAP_ETH
            let data = "0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000201c01bdcaaf021c";
            WrapEthParams::print_decoded_params(&hex::decode(data).unwrap());
            let encode = WrapEthParams {
                recipient: Address::from_str("0x0000000000000000000000000000000000000002").unwrap(),
                amount: U256::from(2313726223222506012u128),
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
        {
            // 0x08: V2_SWAP_EXACT_IN
            let data = "000000000000000000000000459bbf3c1e0f3829bf91ef4f6d0d865d60ab6b87000000000000000000000000000000000000000000000000201c01bdcaaf021c0000000000000000000000000000000000000000000000000004aeedfab7902400000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000e3705d8735ee724a76f3440c0a7ea721ed00";
            V2SwapExactInParams::print_decoded_params(&hex::decode(data).unwrap());
            let encode = V2SwapExactInParams {
                recipient: Address::from_str("0x459bbf3c1e0f3829bf91ef4f6d0d865d60ab6b87").unwrap(),
                amount_in: U256::from(2313726223222506012u128),
                min_amount_out: U256::from(1318237043658788u128),
                path: vec![
                    Address::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                    Address::from_str("0x0000e3705d8735ee724a76f3440c0a7ea721ed00").unwrap(),
                ],
                use_permit2: false,
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
    }

    #[test]
    fn test_encode_decode_permit2_tx3() {
        // https://etherscan.io/tx/0x3b01f14e3c693d650474581dea684a954c25d663330667518b7e9fa13df10355

        // 0x0a080c0604
        {
            // 0x0a: PERMIT2_PERMIT
            let data = "0000000000000000000000003e66c9a569efcf704391b54fd1eebd8ca0556960000000000000000000000000ffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000079eb5d8f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fc91a3afd70395cd496c647d5a6cc9d4b2b7fad0000000000000000000000000000000000000000000000000000000079eb5d8f00000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000004170fd040dace04d798eba1edb5013e6e3bb74d3bef794a0ac03d800417093d80e35624ca55bdd0a4a932497c7675274dccf7211a8d1d061f227bd8170991846301c00000000000000000000000000000000000000000000000000000000000000";
            Permit2PermitParams::print_decoded_params(&hex::decode(data).unwrap());

            let permit_details = PermitDetails {
                token: Address::from_str("0x3e66c9a569efcf704391b54fd1eebd8ca0556960").unwrap(),
                amount: U256::from_str("1461501637330902918203684832716283019655932542975")
                    .unwrap(),
                expiration: U256::from(2045468047),
                nonce: U256::from(0u128),
            };
            let permit_single = PermitSingle {
                details: permit_details,
                spender: Address::from_str("0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad").unwrap(),
                sig_deadline: U256::from(2045468047),
            };
            let encode = Permit2PermitParams {
                permit_single,
                signature: hex::decode("0x70fd040dace04d798eba1edb5013e6e3bb74d3bef794a0ac03d800417093d80e35624ca55bdd0a4a932497c7675274dccf7211a8d1d061f227bd8170991846301c").unwrap(),
            }.encode();
            assert_eq!(data, hex::encode(encode));
        }
        {
            // 0x08: V2_SWAP_EXACT_IN
            let data = "000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000019981b4cf0ea9f06bf24400000000000000000000000000000000000000000000000000000089f91c7f3e8dda00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000003e66c9a569efcf704391b54fd1eebd8ca0556960000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
            V2SwapExactInParams::print_decoded_params(&hex::decode(data).unwrap());

            let encode = V2SwapExactInParams {
                recipient: Address::from_str("0x0000000000000000000000000000000000000002").unwrap(),
                amount_in: U256::from_str("126736174293160000000000000000").unwrap(),
                min_amount_out: U256::from(38835972598566362u128),
                path: vec![
                    Address::from_str("0x3e66c9a569efcf704391b54fd1eebd8ca0556960").unwrap(),
                    Address::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                ],
                use_permit2: true,
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
        {
            // 0x0c: UNWRAP_WETH
            let data = "00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000089f91c7f3e8dda";
            UnwrapWethParams::print_decoded_params(&hex::decode(data).unwrap());
            let encode = UnwrapWethParams {
                recipient: Address::from_str("0x0000000000000000000000000000000000000002").unwrap(),
                min_amount_out: U256::from(38835972598566362u128),
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
        {
            // 0x06: PAY_PORTION
            let data = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a74fa823bc8617fa320a966b3d11b0f722ef09ee000000000000000000000000000000000000000000000000000000000000005a";
            PayPortionParams::print_decoded_params(&hex::decode(data).unwrap());
            let encode = PayPortionParams {
                token: Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                recipient: Address::from_str("0xa74fa823bc8617fa320a966b3d11b0f722ef09ee").unwrap(),
                basis_points: U256::from(90),
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
        {
            // 0x04: SWEEP
            let data = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000088bb38a8154981";
            SweepParams::print_decoded_params(&hex::decode(data).unwrap());

            let encode = SweepParams {
                token: Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                recipient: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
                min_amount_out: U256::from(38486448845179265u128),
            }
            .encode();
            assert_eq!(data, hex::encode(encode));
        }
    }

    #[test]
    fn test_comandsu8_to_command() {
        let cmd = UniswapV3UniversalRouterCommand::try_from(0x00).unwrap();
        println!("{:?}", cmd);
    }
}
