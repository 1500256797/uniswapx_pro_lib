use std::borrow::Cow;

use crate::prelude::*;
use alloy_sol_types::Eip712Domain;

const PERMIT2_DOMAIN_NAME: &str = "Permit2";

pub fn permit2_domain(permit2_address: Address, chain_id: U256) -> Eip712Domain {
    Eip712Domain::new(
        Some(Cow::Borrowed(PERMIT2_DOMAIN_NAME)),
        None,
        Some(chain_id),
        Some(permit2_address),
        None,
    )
}

#[cfg(test)]
mod tests {
    use alloy::{
        dyn_abi::DynSolValue,
        primitives::{bytes, keccak256},
    };
    use permit2_sdk::domain;

    use super::*;

    #[test]
    fn test_domain_separator() {
        let domain = Eip712Domain::new(
            Some(Cow::Borrowed(PERMIT2_DOMAIN_NAME)),
            None,
            Some(U256::from(1)),
            Some(Address::from_str("0x0000000000000000000000000000000000000000").unwrap()),
            None,
        );
        let type_hash = domain.type_hash();
        println!("type_hash: {}", type_hash);
        let domain_separator = domain.hash_struct();
        assert_eq!(
            domain_separator.to_string(),
            "0xa5ed1342e96a6ee3ea989ce263f510f5423d3be0fc366e15ae46811ab03641e5"
        );
    }

    #[test]
    fn test_permit2_domain_hash() {
        {
            let domain = Eip712Domain::new(
                Some(Cow::Borrowed(PERMIT2_DOMAIN_NAME)),
                None,
                Some(U256::from(1)),
                Some(Address::ZERO),
                None,
            );
            let domain_type = domain.encode_type();
            assert_eq!(
                domain_type,
                "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
            );

            let domain_hash = keccak256(domain_type.as_bytes());
            assert_eq!(
                domain_hash.to_string(),
                "0x8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a866"
            );
        }

        {
            let domain = Eip712Domain::new(
                Some(Cow::Borrowed(PERMIT2_DOMAIN_NAME)),
                None,
                Some(U256::from(1)),
                Some(Address::from_str("0xd8b934580fcE35a11B58C6D73aDeE468a2833fa8").unwrap()),
                None,
            );
            // typeHash = keccak256(abi.encode("EIP712Domain(string name,uint256 chainId,address verifyingContract)"));
            // hash_struct = keccak256(abi.encode(typeHash, nameHash, block.chainid, address(this)));
            let domain_separator = domain.hash_struct();
            assert_eq!(
                domain_separator.to_string(),
                "0xf0ace56fb9867a2cc44cf7a492c36c1a4a87e34f1f482461c6067a1619ed3055"
            );
        }
        {
            let domain = Eip712Domain::new(
                Some(Cow::Borrowed(PERMIT2_DOMAIN_NAME)),
                None,
                Some(U256::from(1)),
                Some(Address::from_str("0xd8b934580fcE35a11B58C6D73aDeE468a2833fa8").unwrap()),
                None,
            );
            let domain_separator = domain.hash_struct();
            let message_data = b"";
            let message_hash = keccak256(message_data);
            let eip712_hash =
                keccak256([&[0x19, 0x01], &domain_separator[..], &message_hash[..]].concat());
            assert_eq!(
                hex::encode(eip712_hash),
                "e7774ee3d6576af3dcef4e63dfc3a13b491f41d282910fa02c7c9c83e69da4ad"
            );
        }
    }
}
