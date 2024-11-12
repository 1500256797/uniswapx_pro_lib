use ::eip712::eip712::Eip712;
use alloy::{
    dyn_abi::{DynSolType, DynSolValue},
    primitives::keccak256,
    sol,
};
use alloy_sol_types::{Eip712Domain, SolStruct};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    io::Read,
};
// The main entry points on this contract are:
use crate::prelude::*;
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    PERMIT2,
    "src/abi/Permit2.json"
);

use super::domain::permit2_domain;
pub enum AllowanceTransferEntryPoint {
    /// Approve use apporve when you do not want to set token permissions through signature validation.
    Approve(ApproveFunctionParams),
    /// Permit use permit when you do want to set token permissions through signature validation.
    Permit(SinglePermitFunctionParams),
    /// BatchPermit use permit when you do want to set token permissions through signature validation.
    BatchPermit(BatchPermitFunctionParams),
    /// TransferFrom use transferFrom when you want to transfer a token and have the necessary permissions to do so.
    TransferFrom(SingleTransferFromParams),
    /// BatchTransferFrom use transferFrom when you want to transfer a token and have the necessary permissions to do so.
    BatchTransferFrom(BatchTransferFromParams),
}

pub struct ApproveFunctionParams {
    /// the token address to approve
    pub token: Address,
    /// the spender address to approve
    pub spender: Address,
    /// the approved amount of the token, type(uint160).max is treated as an unlimited allowance
    pub amount: U256,
    /// the timestamp at which the approval is no longer valid, passing in 0 will expire the permissions at block.timestamp
    pub expiration: U64,
}

pub struct SinglePermitFunctionParams {
    /// the address of the token’s owner
    pub owner: Address,
    /// constructed with the following:
    pub permit_single: PermitSingle,
    /// the signature over the permit data
    pub signature: Bytes,
}
#[derive(Serialize, Deserialize)]
pub struct PermitSingle {
    /// the permit data for a single token allowance
    pub details: PermitDetails,
    /// address permissioned on the allowed tokens
    pub spender: Address,
    /// deadline on the permit signature
    pub sig_deadline: U256,
}

#[derive(Serialize, Deserialize)]
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

pub struct BatchPermitFunctionParams {
    /// the address of the token’s owner
    pub owner: Address,
    /// constructed with the following:
    pub permit_batch: PermitBatch,
    /// the signature over the permit data
    pub signature: Bytes,
}

#[derive(Serialize, Deserialize)]
pub struct PermitBatch {
    /// the permit data for multiple token allowances
    pub details: Vec<PermitDetails>,
    /// address permissioned on the allowed tokens
    pub spender: Address,
    /// deadline on the permit signature
    pub sig_deadline: U256,
}

pub struct SingleTransferFromParams {
    /// the address to transfer the token from
    pub from: Address,
    /// the address of the recipient
    pub to: Address,
    /// the amount of the token to transfer, the maximum amount is type(uint160).max
    pub amount: U160,
    /// the address of the token to be transferred
    pub token: Address,
}
pub struct BatchTransferFromParams {
    /// the allowance transfer details
    pub transfer_details: Vec<AllowanceTransferDetails>,
}

pub struct AllowanceTransferDetails {
    /// the owner of the token
    pub from: Address,
    /// the recipient of the token
    pub to: Address,
    /// the amount of the token
    pub amount: U160,
    /// the token to be transferred
    pub token: Address,
}

pub enum PermitType {
    PermitSingle(PermitSingle),
    PermitBatch(PermitBatch),
}

pub fn hash(permit_type: PermitType, permit2_address: Address, chain_id: U256) -> String {
    match permit_type {
        PermitType::PermitSingle(permit) => {
            let mut types: BTreeMap<String, Vec<eip712::Eip712DomainType>> = BTreeMap::new();
            let mut message: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            types.insert(
                "EIP712Domain".to_string(),
                vec![
                    eip712::Eip712DomainType {
                        name: "name".to_string(),
                        r#type: "string".to_string(),
                    },
                    eip712::Eip712DomainType {
                        name: "chainId".to_string(),
                        r#type: "uint256".to_string(),
                    },
                    eip712::Eip712DomainType {
                        name: "verifyingContract".to_string(),
                        r#type: "address".to_string(),
                    },
                ],
            );
            types.insert(
                "PermitDetails".to_string(),
                vec![
                    eip712::Eip712DomainType {
                        name: "token".to_string(),
                        r#type: "address".to_string(),
                    },
                    eip712::Eip712DomainType {
                        name: "amount".to_string(),
                        r#type: "uint160".to_string(),
                    },
                    eip712::Eip712DomainType {
                        name: "expiration".to_string(),
                        r#type: "uint48".to_string(),
                    },
                    eip712::Eip712DomainType {
                        name: "nonce".to_string(),
                        r#type: "uint48".to_string(),
                    },
                ],
            );
            types.insert(
                "PermitSingle".to_string(),
                vec![
                    eip712::Eip712DomainType {
                        name: "details".to_string(),
                        r#type: "PermitDetails".to_string(),
                    },
                    eip712::Eip712DomainType {
                        name: "spender".to_string(),
                        r#type: "address".to_string(),
                    },
                    eip712::Eip712DomainType {
                        name: "sigDeadline".to_string(),
                        r#type: "uint256".to_string(),
                    },
                ],
            );

            let details = serde_json::json!({
                "token": format!("{:?}", permit.details.token),
                "amount": permit.details.amount.to_string(),
                "expiration": permit.details.expiration.to_string(),
                "nonce": permit.details.nonce.to_string()
            });
            message.insert("details".to_string(), details);
            message.insert(
                "spender".to_string(),
                serde_json::from_value(serde_json::Value::String(format!("{:?}", permit.spender)))
                    .unwrap(),
            );
            message.insert(
                "sigDeadline".to_string(),
                serde_json::from_value(serde_json::Value::String(permit.sig_deadline.to_string()))
                    .unwrap(),
            );
            let typed_data = eip712::TypedData {
                domain: eip712::EIP712Domain {
                    name: Some("Permit2".to_string()),
                    chain_id: Some(
                        ethabi::ethereum_types::U256::from_str(&chain_id.to_string()).unwrap(),
                    ),
                    version: None,
                    verifying_contract: Some(permit2_address.to_string()),
                    salt: None,
                },
                types,
                primary_type: "PermitSingle".to_string(),
                message,
            };
            let type_hash =
                ::eip712::eip712::hash_type(&typed_data.primary_type, &typed_data.types).unwrap();
            assert_eq!(
                "f3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d0",
                hex::encode(type_hash)
            );
            let hash = typed_data.encode_eip712().unwrap();
            hex::encode(&hash[..])
        }
        PermitType::PermitBatch(permit) => todo!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_uniswap_sell_token_permit_single_hash() {
        let universal_router = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"
            .parse()
            .unwrap();
        let ethcoin = "0xE957ea0b072910f508dD2009F4acB7238C308E29"
            .parse()
            .unwrap();
        let permit = PermitSingle {
            details: PermitDetails {
                token: ethcoin,
                amount: U256::from_str("1461501637330902918203684832716283019655932542975")
                    .unwrap(),
                expiration: U256::from_str("1734011793").unwrap(),
                nonce: U256::from_str("0").unwrap(),
            },
            spender: universal_router,
            sig_deadline: U256::from_str("1731421593").unwrap(),
        };

        let hash = hash(
            PermitType::PermitSingle(permit),
            "0x000000000022D473030F116dDEE9F6B43aC78BA3"
                .parse()
                .unwrap(),
            U256::from(1),
        );
        assert_eq!(
            hash,
            "d2e7a265a8e9ecb533e846309a14f0c034fee3e4ecb3f985755dae05b7a4804d".to_string()
        );
    }
}
