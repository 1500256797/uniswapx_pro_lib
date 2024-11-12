use super::human_readable::lexer::HumanReadableParser;
use super::serde_helpers::deserialize_salt_opt;
use super::serde_helpers::deserialize_stringified_array_opt;
use super::serde_helpers::deserialize_stringified_numeric_opt;
use super::serde_helpers::StringifiedNumeric;
use super::types::bytes::Bytes;

use ethabi::encode;
use ethabi::ParamType;
use ethabi::Token;

use core::iter::FromIterator;
use core::str::FromStr;
use hex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::format;
use std::string::String;
use std::string::ToString;
use std::vec;
use std::vec::Vec;
use thiserror;

use cryptoxide::digest::Digest;
use cryptoxide::sha3::Keccak256;
use ethabi::ethereum_types::{Address, U256};

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.input(input);
    let mut output = [0u8; 32];
    hasher.result(&mut output);
    output
}

/// Custom types for `TypedData`
pub type Types = BTreeMap<String, Vec<Eip712DomainType>>;

/// Pre-computed value of the following expression:
///
/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address
/// verifyingContract)")`
pub const EIP712_DOMAIN_TYPE_HASH: [u8; 32] = [
    139, 115, 195, 198, 155, 184, 254, 61, 81, 46, 204, 76, 247, 89, 204, 121, 35, 159, 123, 23,
    155, 15, 250, 202, 169, 167, 93, 82, 43, 57, 64, 15,
];

/// Pre-computed value of the following expression:
///
/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address
/// verifyingContract,bytes32 salt)")`
pub const EIP712_DOMAIN_TYPE_HASH_WITH_SALT: [u8; 32] = [
    216, 124, 214, 239, 121, 212, 226, 185, 94, 21, 206, 138, 191, 115, 45, 181, 30, 199, 113, 241,
    202, 46, 220, 207, 34, 164, 108, 114, 154, 197, 100, 114,
];

/// An EIP-712 error.
#[derive(Debug, thiserror::Error)]
pub enum Eip712Error {
    #[error("Error from Eip712 struct: {0:?}")]
    Message(String),
}

/// Helper methods for computing the typed data hash used in `eth_signTypedData`.
///
/// The ethers-rs `derive_eip712` crate provides a derive macro to
/// implement the trait for a given struct. See documentation
/// for `derive_eip712` for more information and example usage.
///
/// For those who wish to manually implement this trait, see:
/// <https://eips.ethereum.org/EIPS/eip-712>
///
/// Any rust struct implementing Eip712 must also have a corresponding
/// struct in the verifying ethereum contract that matches its signature.
pub trait Eip712 {
    /// User defined error type;
    type Error: std::error::Error + Send + Sync + std::fmt::Debug;

    /// Default implementation of the domain separator;
    fn domain_separator(&self, types: Option<&Types>) -> Result<[u8; 32], Self::Error> {
        Ok(self.domain()?.separator(types))
    }

    /// Returns the current domain. The domain depends on the contract and unique domain
    /// for which the user is targeting. In the derive macro, these attributes
    /// are passed in as arguments to the macro. When manually deriving, the user
    /// will need to know the name of the domain, version of the contract, chain ID of
    /// where the contract lives and the address of the verifying contract.
    fn domain(&self) -> Result<EIP712Domain, Self::Error>;

    /// This method is used for calculating the hash of the type signature of the
    /// struct. The field types of the struct must map to primitive
    /// ethereum types or custom types defined in the contract.
    fn type_hash() -> Result<[u8; 32], Self::Error>;

    /// Hash of the struct, according to EIP-712 definition of `hashStruct`
    fn struct_hash(&self) -> Result<[u8; 32], Self::Error>;

    /// When using the derive macro, this is the primary method used for computing the final
    /// EIP-712 encoded payload. This method relies on the aforementioned methods for computing
    /// the final encoded payload.
    fn encode_eip712(&self) -> Result<[u8; 32], Self::Error> {
        // encode the digest to be compatible with solidity abi.encodePacked()
        // See: https://github.com/gakonst/ethers-rs/blob/master/examples/permit_hash.rs#L72

        let domain_separator = self.domain_separator(None)?;
        let struct_hash = self.struct_hash()?;

        let digest_input = [&[0x19, 0x01], &domain_separator[..], &struct_hash[..]].concat();

        Ok(keccak256(digest_input.as_ref()))
    }
}

/// Eip712 Domain attributes used in determining the domain separator;
/// Unused fields are left out of the struct type.
///
/// Protocol designers only need to include the fields that make sense for their signing domain.
/// Unused fields are left out of the struct type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EIP712Domain {
    ///  The user readable name of signing domain, i.e. the name of the DApp or the protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The current major version of the signing domain. Signatures from different versions are not
    /// compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// The EIP-155 chain id. The user-agent should refuse signing if it does not match the
    /// currently active chain.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_stringified_numeric_opt"
    )]
    pub chain_id: Option<U256>,

    /// The address of the contract that will verify the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_contract: Option<String>,

    /// A disambiguating salt for the protocol. This can be used as a domain separator of last
    /// resort.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_salt_opt"
    )]
    pub salt: Option<[u8; 32]>,
}

impl EIP712Domain {
    // Compute the domain separator;
    // See: https://github.com/gakonst/ethers-rs/blob/master/examples/permit_hash.rs#L41
    pub fn separator(&self, types: Option<&Types>) -> [u8; 32] {
        // full name is `EIP712Domain(string name,string version,uint256 chainId,address
        // verifyingContract,bytes32 salt)`
        let mut ty = "EIP712Domain(".to_string();
        let mut tokens = Vec::new();
        let mut needs_comma = false;
        // depends on the order of the fields in the types
        if let Some(types) = types {
            if let Some(fields) = types.get("EIP712Domain") {
                for field in fields {
                    // add the field to the type string in the field order
                    match field.r#name.as_str() {
                        "name" => {
                            if needs_comma {
                                ty.push(',');
                            }
                            ty += format!("{} name", field.r#type.clone()).as_str();
                            let name = self.name.as_ref().unwrap();
                            tokens.push(Token::Uint(U256::from(keccak256(name.as_ref()))));
                            needs_comma = true;
                        }
                        "version" => {
                            if needs_comma {
                                ty.push(',');
                            }
                            ty += format!("{} version", field.r#type.clone()).as_str();
                            let version = self.version.as_ref().unwrap();
                            tokens.push(Token::Uint(U256::from(keccak256(version.as_ref()))));
                            needs_comma = true;
                        }
                        "chainId" => {
                            if needs_comma {
                                ty.push(',');
                            }
                            ty += format!("{} chainId", field.r#type.clone()).as_str();
                            let chain_id = self.chain_id.unwrap();
                            tokens.push(Token::Uint(chain_id));
                            needs_comma = true;
                        }
                        "verifyingContract" => {
                            if needs_comma {
                                ty.push(',');
                            }
                            let addr_str = "address".to_string();
                            let t = field.r#type.clone();
                            ty += format!("{} verifyingContract", t).as_str();
                            let verifying_contract = self.verifying_contract.as_ref().unwrap();
                            if t == "address" {
                                tokens.push(Token::Address(
                                    Address::from_str(verifying_contract.as_str())
                                        .unwrap_or_default(),
                                ));
                            } else {
                                tokens.push(Token::Uint(U256::from(keccak256(
                                    verifying_contract.as_ref(),
                                ))));
                            }
                            needs_comma = true;
                        }
                        "salt" => {
                            if needs_comma {
                                ty.push(',');
                            }
                            ty += format!("{} salt", field.r#type.clone()).as_str();
                            tokens.push(Token::Uint(U256::from(self.salt.unwrap())));
                        }

                        _ => {}
                    }
                }
            }
        }
        ty.push(')');

        tokens.insert(0, Token::Uint(U256::from(keccak256(ty.as_ref()))));

        keccak256(encode(&tokens).as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct EIP712WithDomain<T>
where
    T: Clone + Eip712,
{
    pub domain: EIP712Domain,
    pub inner: T,
}

impl<T: Eip712 + Clone> EIP712WithDomain<T> {
    pub fn new(inner: T) -> Result<Self, Eip712Error> {
        let domain = inner
            .domain()
            .map_err(|e| Eip712Error::Message(e.to_string()))?;

        Ok(Self { domain, inner })
    }

    #[must_use]
    pub fn set_domain(self, domain: EIP712Domain) -> Self {
        Self {
            domain,
            inner: self.inner,
        }
    }
}

impl<T: Eip712 + Clone> Eip712 for EIP712WithDomain<T> {
    type Error = Eip712Error;

    fn domain(&self) -> Result<EIP712Domain, Self::Error> {
        Ok(self.domain.clone())
    }

    fn type_hash() -> Result<[u8; 32], Self::Error> {
        let type_hash = T::type_hash().map_err(|e| Self::Error::Message(e.to_string()))?;
        Ok(type_hash)
    }

    fn struct_hash(&self) -> Result<[u8; 32], Self::Error> {
        let struct_hash = self
            .inner
            .clone()
            .struct_hash()
            .map_err(|e| Self::Error::Message(e.to_string()))?;
        Ok(struct_hash)
    }
}

/// Represents the [EIP-712](https://eips.ethereum.org/EIPS/eip-712) typed data object.
///
/// Typed data is a JSON object containing type information, domain separator parameters and the
/// message object which has the following schema
///
/// ```json
/// {
///     "type": "object",
///     "properties": {
///         "types": {
///             "type": "object",
///             "properties": {
///                 "EIP712Domain": { "type": "array" }
///             },
///             "additionalProperties": {
///                 "type": "array",
///                 "items": {
///                     "type": "object",
///                     "properties": {
///                         "name": { "type": "string" },
///                         "type": { "type": "string" }
///                     },
///                     "required": ["name", "type"]
///                 }
///             },
///             "required": ["EIP712Domain"]
///         },
///         "primaryType": { "type": "string" },
///         "domain": { "type": "object" },
///         "message": { "type": "object" }
///     },
///     "required": ["types", "primaryType", "domain", "message"]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypedData {
    /// Signing domain metadata. The signing domain is the intended context for the signature (e.g.
    /// the dapp, protocol, etc. that it's intended for). This data is used to construct the domain
    /// seperator of the message.
    pub domain: EIP712Domain,
    /// The custom types used by this message.
    pub types: Types,
    #[serde(rename = "primaryType")]
    /// The type of the message.
    pub primary_type: String,
    /// The message to be signed.
    pub message: BTreeMap<String, serde_json::Value>,
}

/// According to the MetaMask implementation,
/// the message parameter may be JSON stringified in versions later than V1
/// See <https://github.com/MetaMask/metamask-extension/blob/0dfdd44ae7728ed02cbf32c564c75b74f37acf77/app/scripts/metamask-controller.js#L1736>
/// In fact, ethers.js JSON stringifies the message at the time of writing.
impl<'de> Deserialize<'de> for TypedData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        struct TypedDataHelper {
            domain: EIP712Domain,
            types: Types,
            #[serde(rename = "primaryType")]
            primary_type: String,
            message: BTreeMap<String, serde_json::Value>,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Type {
            Val(TypedDataHelper),
            String(String),
        }

        match Type::deserialize(deserializer)? {
            Type::Val(v) => {
                let TypedDataHelper {
                    domain,
                    types,
                    primary_type,
                    message,
                } = v;
                Ok(TypedData {
                    domain,
                    types,
                    primary_type,
                    message,
                })
            }
            Type::String(s) => {
                let TypedDataHelper {
                    domain,
                    types,
                    primary_type,
                    message,
                } = serde_json::from_str(&s).map_err(serde::de::Error::custom)?;
                Ok(TypedData {
                    domain,
                    types,
                    primary_type,
                    message,
                })
            }
        }
    }
}

// === impl TypedData ===

impl Eip712 for TypedData {
    type Error = Eip712Error;

    fn domain(&self) -> Result<EIP712Domain, Self::Error> {
        Ok(self.domain.clone())
    }

    fn type_hash() -> Result<[u8; 32], Self::Error> {
        Err(Eip712Error::Message("dynamic type".to_string()))
    }

    fn struct_hash(&self) -> Result<[u8; 32], Self::Error> {
        let tokens = encode_data(
            &self.primary_type,
            &serde_json::Value::Object(serde_json::Map::from_iter(self.message.clone())),
            &self.types,
        )?;

        Ok(keccak256(encode(&tokens).as_ref()))
    }

    /// Hash a typed message according to EIP-712. The returned message starts with the EIP-712
    /// prefix, which is "1901", followed by the hash of the domain separator, then the data (if
    /// any). The result is hashed again and returned.
    fn encode_eip712(&self) -> Result<[u8; 32], Self::Error> {
        let domain_separator = self.domain.separator(Some(&self.types));
        println!("domain_separator: {:?}", hex::encode(domain_separator));
        let mut digest_input = [&[0x19, 0x01], &domain_separator[..]].concat().to_vec();

        if self.primary_type != "EIP712Domain" {
            // compatibility with <https://github.com/MetaMask/eth-sig-util>
            digest_input.extend(&self.struct_hash()?[..])
        }
        Ok(keccak256(digest_input.as_ref()))
    }
}

/// Represents the name and type pair
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Eip712DomainType {
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Encodes an object by encoding and concatenating each of its members.
///
/// The encoding of a struct instance is `enc(value₁) ‖ enc(value₂) ‖ … ‖ enc(valueₙ)`, i.e. the
/// concatenation of the encoded member values in the order that they appear in the type. Each
/// encoded member value is exactly 32-byte long.
///
///   - `primaryType`: The root type.
///   - `data`: The object to encode.
///   - `types`: Type definitions for all types included in the message.
///
/// Returns an encoded representation of an object
pub fn encode_data(
    primary_type: &str,
    data: &serde_json::Value,
    types: &Types,
) -> Result<Vec<Token>, Eip712Error> {
    let hash = hash_type(primary_type, types)?;
    let mut tokens = vec![Token::Uint(U256::from(hash))];

    if let Some(fields) = types.get(primary_type) {
        for field in fields {
            // handle recursive types
            if let Some(value) = data.get(&field.name) {
                let field = encode_field(types, &field.name, &field.r#type, value)?;
                tokens.push(field);
            } else if types.contains_key(&field.r#type) {
                tokens.push(Token::Uint(U256::zero()));
            } else {
                return Err(Eip712Error::Message(format!(
                    "No data found for: `{}`",
                    field.name
                )));
            }
        }
    }

    Ok(tokens)
}

/// Hashes an object
///
///   - `primary_type`: The root type to encode.
///   - `data`: The object to hash.
///   - `types`: All type definitions.
///
/// Returns the hash of the `primary_type` object
pub fn hash_struct(
    primary_type: &str,
    data: &serde_json::Value,
    types: &Types,
) -> Result<[u8; 32], Eip712Error> {
    let tokens = encode_data(primary_type, data, types)?;
    let encoded = encode(&tokens);
    Ok(keccak256(encoded.as_ref()))
}

/// Returns the hashed encoded type of `primary_type`
pub fn hash_type(primary_type: &str, types: &Types) -> Result<[u8; 32], Eip712Error> {
    encode_type(primary_type, types).map(|result| keccak256(result.as_ref()))
}

///  Encodes the type of an object by encoding a comma delimited list of its members.
///
///   - `primary_type`: The root type to encode.
///   - `types`: All type definitions.
///
/// Returns the encoded representation of the field.
pub fn encode_type(primary_type: &str, types: &Types) -> Result<String, Eip712Error> {
    let mut names = BTreeSet::new();
    find_type_dependencies(primary_type, types, &mut names);
    // need to ensure primary_type is first in the list
    names.remove(primary_type);
    let mut deps: Vec<_> = names.into_iter().collect();
    deps.sort_unstable();
    deps.insert(0, primary_type);

    let mut res = String::new();

    for dep in deps.into_iter() {
        let fields = types.get(dep).ok_or_else(|| {
            Eip712Error::Message(format!("No type definition found for: `{dep}`"))
        })?;

        res += dep;
        res.push('(');
        res += &fields
            .iter()
            .map(|ty| format!("{} {}", ty.r#type, ty.name))
            .collect::<Vec<_>>()
            .join(",");

        res.push(')');
    }

    Ok(res)
}

/// Returns all the custom types used in the `primary_type`
fn find_type_dependencies<'a>(
    primary_type: &'a str,
    types: &'a Types,
    found: &mut BTreeSet<&'a str>,
) {
    if found.contains(primary_type) {
        return;
    }
    if let Some(fields) = types.get(primary_type) {
        found.insert(primary_type);
        for field in fields {
            // need to strip the array tail
            let ty = field.r#type.split('[').next().unwrap();
            find_type_dependencies(ty, types, found)
        }
    }
}

/// Encode a single field.
///
///   - `types`: All type definitions.
///   - `field`: The name and type of the field being encoded.
///   - `value`: The value to encode.
///
/// Returns the encoded representation of the field.
pub fn encode_field(
    types: &Types,
    _field_name: &str,
    field_type: &str,
    value: &serde_json::Value,
) -> Result<Token, Eip712Error> {
    let token = {
        // check if field is custom data type
        if types.contains_key(field_type) {
            let tokens = encode_data(field_type, value, types)?;
            let encoded = encode(&tokens);
            encode_eip712_type(Token::Bytes(encoded.to_vec()))
        } else {
            match field_type {
                s if s.contains('[') => {
                    let (stripped_type, _) = s.rsplit_once('[').unwrap();
                    // ensure value is an array
                    let values = value.as_array().ok_or_else(|| {
                        Eip712Error::Message(format!(
                            "Expected array for type `{s}`, but got `{value}`",
                        ))
                    })?;
                    let tokens = values
                        .iter()
                        .map(|value| encode_field(types, _field_name, stripped_type, value))
                        .collect::<Result<Vec<_>, _>>()?;

                    let encoded = encode(&tokens);
                    encode_eip712_type(Token::Bytes(encoded))
                }
                s => {
                    // parse as param type
                    let param = HumanReadableParser::parse_type(s).map_err(|err| {
                        Eip712Error::Message(format!("Failed to parse type {s}: {err}",))
                    })?;
                    match param {
                        ParamType::Address => {
                            Token::Address(serde_json::from_value(value.clone()).map_err(
                                |err| Eip712Error::Message(format!("serde_json::from_value {err}")),
                            )?)
                        }
                        ParamType::Bytes => {
                            let data: Bytes =
                                serde_json::from_value(value.clone()).map_err(|err| {
                                    Eip712Error::Message(format!("serde_json::from_value {err}"))
                                })?;
                            encode_eip712_type(Token::Bytes(data.0.to_vec()))
                        }
                        ParamType::Int(size) => {
                            let val: StringifiedNumeric = serde_json::from_value(value.clone())
                                .map_err(|err| {
                                    Eip712Error::Message(format!("serde_json::from_value {err}"))
                                })?;

                            match size {
                                128 => {
                                    let val: i128 = val.try_into().map_err(|err| {
                                        Eip712Error::Message(format!("Failed to parse int {err}"))
                                    })?;
                                    if val < 0 {
                                        let positive_val = val.wrapping_neg();
                                        let u256_val = U256::from(positive_val);
                                        let val_as_u256 = !u256_val + U256::one();
                                        Token::Uint(val_as_u256)
                                    } else {
                                        let val: U256 = val.try_into().map_err(|err| {
                                            Eip712Error::Message(format!(
                                                "Failed to parse int {err}"
                                            ))
                                        })?;
                                        Token::Uint(val)
                                    }
                                }
                                _ => {
                                    let val: U256 = val.try_into().map_err(|err| {
                                        Eip712Error::Message(format!("Failed to parse int {err}"))
                                    })?;

                                    Token::Uint(val)
                                }
                            }
                        }
                        ParamType::Uint(_) => {
                            // uints are commonly stringified due to how ethers-js encodes
                            let val: StringifiedNumeric = serde_json::from_value(value.clone())
                                .map_err(|err| {
                                    Eip712Error::Message(format!("serde_json::from_value {err}"))
                                })?;
                            let val = val.try_into().map_err(|err| {
                                Eip712Error::Message(format!("Failed to parse uint {err}"))
                            })?;

                            Token::Uint(val)
                        }
                        ParamType::Bool => encode_eip712_type(Token::Bool(
                            serde_json::from_value(value.clone()).map_err(|err| {
                                Eip712Error::Message(format!("serde_json::from_value {err}"))
                            })?,
                        )),
                        ParamType::String => {
                            let s: String =
                                serde_json::from_value(value.clone()).map_err(|err| {
                                    Eip712Error::Message(format!("serde_json::from_value {err}"))
                                })?;
                            encode_eip712_type(Token::String(s))
                        }
                        ParamType::FixedArray(_, _) | ParamType::Array(_) => {
                            unreachable!("is handled in separate arm")
                        }
                        ParamType::FixedBytes(_) => {
                            let data: Bytes =
                                serde_json::from_value(value.clone()).map_err(|err| {
                                    Eip712Error::Message(format!("serde_json::from_value {err}"))
                                })?;
                            encode_eip712_type(Token::FixedBytes(data.0.to_vec()))
                        }
                        ParamType::Tuple(_) => {
                            return Err(Eip712Error::Message(
                                format!("Unexpected tuple type {s}",),
                            ));
                        }
                    }
                }
            }
        }
    };

    Ok(token)
}

/// Convert hash map of field names and types into a type hash corresponding to enc types;
pub fn make_type_hash(primary_type: String, fields: &[(String, ParamType)]) -> [u8; 32] {
    let parameters = fields
        .iter()
        .map(|(k, v)| format!("{v} {k}"))
        .collect::<Vec<String>>()
        .join(",");

    let sig = format!("{primary_type}({parameters})");

    keccak256(sig.as_ref())
}

/// Parse token into Eip712 compliant ABI encoding
pub fn encode_eip712_type(token: Token) -> Token {
    match token {
        Token::Bytes(t) => Token::Uint(U256::from(keccak256(t.as_ref()))),
        Token::FixedBytes(t) => Token::Uint(U256::from(&t[..])),
        Token::String(t) => Token::Uint(U256::from(keccak256(t.as_ref()))),
        Token::Bool(t) => {
            // Boolean false and true are encoded as uint256 values 0 and 1 respectively
            Token::Uint(U256::from(t as i32))
        }
        Token::Int(t) => {
            // Integer values are sign-extended to 256-bit and encoded in big endian order.
            Token::Uint(t)
        }
        Token::Array(tokens) => Token::Uint(U256::from(keccak256(
            encode(
                &tokens
                    .into_iter()
                    .map(encode_eip712_type)
                    .collect::<Vec<Token>>(),
            )
            .as_ref(),
        ))),
        Token::FixedArray(tokens) => Token::Uint(U256::from(keccak256(
            encode(
                &tokens
                    .into_iter()
                    .map(encode_eip712_type)
                    .collect::<Vec<Token>>(),
            )
            .as_ref(),
        ))),
        Token::Tuple(tuple) => {
            let tokens = tuple
                .into_iter()
                .map(encode_eip712_type)
                .collect::<Vec<Token>>();
            let encoded = encode(&tokens);
            Token::Uint(U256::from(keccak256(encoded.as_ref())))
        }
        _ => {
            // Return the ABI encoded token;
            token
        }
    }
}

// Adapted tests from <https://github.com/MetaMask/eth-sig-util/blob/main/src/sign-typed-data.test.ts>
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::println;

    #[test]
    fn test_full_domain() {
        let json = serde_json::json!({
          "types": {
            "EIP712Domain": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "version",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              },
              {
                "name": "salt",
                "type": "bytes32"
              }
            ]
          },
          "primaryType": "EIP712Domain",
          "domain": {
            "name": "example.metamask.io",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0x0000000000000000000000000000000000000000",
                "salt": "0x01020300"
          },
          "message": {}
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "7529a15e7b8fd752f395945d3e61458ba0d8734766dc4a1d99ac727061ff758c",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn test_minimal_message() {
        let json = serde_json::json!( {"types":{"EIP712Domain":[]},"primaryType":"EIP712Domain","domain":{},"message":{}});

        let typed_data: TypedData = serde_json::from_value(json).unwrap();

        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "8d4a3f4082945b7879e2b55f181c31a77c8c0a464b70669458abbaaf99de4c38",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn test_encode_custom_array_type() {
        let json = serde_json::json!({"domain":{},"types":{"EIP712Domain":[],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address[]"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person[]"},{"name":"contents","type":"string"}]},"primaryType":"Mail","message":{"from":{"name":"Cow","wallet":["0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826","0xDD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"]},"to":[{"name":"Bob","wallet":["0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"]}],"contents":"Hello, Bob!"}});

        let typed_data: TypedData = serde_json::from_value(json).unwrap();

        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "80a3aeb51161cfc47884ddf8eac0d2343d6ae640efe78b6a69be65e3045c1321",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn test_hash_typed_message_with_data() {
        let json = serde_json::json!( {
          "types": {
            "EIP712Domain": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "version",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              }
            ],
            "Message": [
              {
                "name": "data",
                "type": "string"
              }
            ]
          },
          "primaryType": "Message",
          "domain": {
            "name": "example.metamask.io",
            "version": "1",
            "chainId": "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000"
          },
          "message": {
            "data": "Hello!"
          }
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();

        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "232cd3ec058eb935a709f093e3536ce26cc9e8e193584b0881992525f6236eef",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn test_hash_no_standard_typed_message_with_data() {
        let json = serde_json::json!( {
          "types": {
            "EIP712Domain": [
              {
                "name": "version",
                "type": "string"
              },
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              }
            ],
            "Message": [
              {
                "name": "data",
                "type": "string"
              }
            ]
          },
          "primaryType": "Message",
          "domain": {
            "name": "example.metamask.io",
            "version": "1",
            "chainId": "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000"
          },
          "message": {
            "data": "Hello!"
          }
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "b88c7d69a075615bb1a29e38d4b3be4ed4ca51471aaa72918f6da232cd845d19",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn test_hash_no_standard_typed_message_with_data2() {
        let json = serde_json::json!( {"types":{"EIP712Domain":[{"name":"chainId","type":"uint256"},{"name":"name","type":"string"},{"name":"verifyingContract","type":"address"},{"name":"version","type":"string"}],"Action":[{"name":"action","type":"string"},{"name":"params","type":"string"}],"Cell":[{"name":"capacity","type":"string"},{"name":"lock","type":"string"},{"name":"type","type":"string"},{"name":"data","type":"string"},{"name":"extraData","type":"string"}],"Transaction":[{"name":"DAS_MESSAGE","type":"string"},{"name":"inputsCapacity","type":"string"},{"name":"outputsCapacity","type":"string"},{"name":"fee","type":"string"},{"name":"action","type":"Action"},{"name":"inputs","type":"Cell[]"},{"name":"outputs","type":"Cell[]"},{"name":"digest","type":"bytes32"}]},"primaryType":"Transaction","domain":{"chainId":1,"name":"da.systems","verifyingContract":"0x0000000000000000000000000000000020210722","version":"1"},"message":{"DAS_MESSAGE":"TRANSFER FROM 0x54366bcd1e73baf55449377bd23123274803236e(906.74221046 CKB) TO ckt1qyqvsej8jggu4hmr45g4h8d9pfkpd0fayfksz44t9q(764.13228446 CKB), 0x54366bcd1e73baf55449377bd23123274803236e(142.609826 CKB)","inputsCapacity":"906.74221046 CKB","outputsCapacity":"906.74211046 CKB","fee":"0.0001 CKB","digest":"0x29cd28dbeb470adb17548563ceb4988953fec7b499e716c16381e5ae4b04021f","action":{"action":"transfer","params":"0x00"},"inputs":[],"outputs":[]}}
        );
        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "9f1a1bc718e966d683c544aef6fd0b73c85a1d6244af9b64bb8f4a6fa6716086",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn test_hash_custom_data_type() {
        let json = serde_json::json!(  {"domain":{},"types":{"EIP712Domain":[],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}});

        let typed_data: TypedData = serde_json::from_value(json).unwrap();

        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "25c3d40a39e639a4d0b6e4d2ace5e1281e039c88494d97d8d08f99a6ea75d775",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn test_hash_recursive_types() {
        let json = serde_json::json!( {
          "domain": {},
          "types": {
            "EIP712Domain": [],
            "Person": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "wallet",
                "type": "address"
              }
            ],
            "Mail": [
              {
                "name": "from",
                "type": "Person"
              },
              {
                "name": "to",
                "type": "Person"
              },
              {
                "name": "contents",
                "type": "string"
              },
              {
                "name": "replyTo",
                "type": "Mail"
              }
            ]
          },
          "primaryType": "Mail",
          "message": {
            "from": {
              "name": "Cow",
              "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
            },
            "to": {
              "name": "Bob",
              "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
            },
            "contents": "Hello, Bob!",
            "replyTo": {
              "to": {
                "name": "Cow",
                "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
              },
              "from": {
                "name": "Bob",
                "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
              },
              "contents": "Hello!"
            }
          }
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "0808c17abba0aef844b0470b77df9c994bc0fa3e244dc718afd66a3901c4bd7b",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn test_hash_nested_struct_array() {
        let json = serde_json::json!({
          "types": {
            "EIP712Domain": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "version",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              }
            ],
            "OrderComponents": [
              {
                "name": "offerer",
                "type": "address"
              },
              {
                "name": "zone",
                "type": "address"
              },
              {
                "name": "offer",
                "type": "OfferItem[]"
              },
              {
                "name": "startTime",
                "type": "uint256"
              },
              {
                "name": "endTime",
                "type": "uint256"
              },
              {
                "name": "zoneHash",
                "type": "bytes32"
              },
              {
                "name": "salt",
                "type": "uint256"
              },
              {
                "name": "conduitKey",
                "type": "bytes32"
              },
              {
                "name": "counter",
                "type": "uint256"
              }
            ],
            "OfferItem": [
              {
                "name": "token",
                "type": "address"
              }
            ],
            "ConsiderationItem": [
              {
                "name": "token",
                "type": "address"
              },
              {
                "name": "identifierOrCriteria",
                "type": "uint256"
              },
              {
                "name": "startAmount",
                "type": "uint256"
              },
              {
                "name": "endAmount",
                "type": "uint256"
              },
              {
                "name": "recipient",
                "type": "address"
              }
            ]
          },
          "primaryType": "OrderComponents",
          "domain": {
            "name": "Seaport",
            "version": "1.1",
            "chainId": "1",
            "verifyingContract": "0x00000000006c3852cbEf3e08E8dF289169EdE581"
          },
          "message": {
            "offerer": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "offer": [
              {
                "token": "0xA604060890923Ff400e8c6f5290461A83AEDACec"
              }
            ],
            "startTime": "1658645591",
            "endTime": "1659250386",
            "zone": "0x004C00500000aD104D7DBd00e3ae0A5C00560C00",
            "zoneHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "salt": "16178208897136618",
            "conduitKey": "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000",
            "totalOriginalConsiderationItems": "2",
            "counter": "0"
          }
        }
                );
        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "0b8aa9f3712df0034bc29fe5b24dd88cfdba02c7f499856ab24632e2969709a8",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn test_hash_nested_struct() {
        let json = serde_json::json!({

            "domain": {
                "chainId": 1100,
                "name": "Cosmos Web3",
                "salt": "0",
                "verifyingContract": "cosmos",
                "version": "1.0.0"
            },
            "message": {
                "account_number": "855752",
                "chain_id": "dymension_1100-1",
                "fee": {
                    "amount": [
                        {
                            "amount": "2527440000000000",
                            "denom": "adym"
                        }
                    ],
                    "feePayer": "dym1g65rdfk4sqxa82u6dwg5eyzwlqqhkjxggf4u0y",
                    "gas": "126372"
                },
                "memo": "",
                "msgs": [
                    {
                        "type": "cosmos-sdk/MsgVote",
                        "value": {
                            "option": 3,
                            "proposal_id": 12,
                            "voter": "dym1g65rdfk4sqxa82u6dwg5eyzwlqqhkjxggf4u0y"
                        }
                    }
                ],
                "sequence": "4"
            },
            "primaryType": "Tx",
            "types": {
                "Coin": [
                    {
                        "name": "denom",
                        "type": "string"
                    },
                    {
                        "name": "amount",
                        "type": "string"
                    }
                ],
                "EIP712Domain": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "version",
                        "type": "string"
                    },
                    {
                        "name": "chainId",
                        "type": "uint256"
                    },
                    {
                        "name": "verifyingContract",
                        "type": "string"
                    },
                    {
                        "name": "salt",
                        "type": "string"
                    }
                ],
                "Fee": [
                    {
                        "name": "feePayer",
                        "type": "string"
                    },
                    {
                        "name": "amount",
                        "type": "Coin[]"
                    },
                    {
                        "name": "gas",
                        "type": "string"
                    }
                ],
                "Msg": [
                    {
                        "name": "type",
                        "type": "string"
                    },
                    {
                        "name": "value",
                        "type": "MsgValue"
                    }
                ],
                "MsgValue": [
                    {
                        "name": "proposal_id",
                        "type": "uint64"
                    },
                    {
                        "name": "voter",
                        "type": "string"
                    },
                    {
                        "name": "option",
                        "type": "int32"
                    }
                ],
                "Tx": [
                    {
                        "name": "account_number",
                        "type": "string"
                    },
                    {
                        "name": "chain_id",
                        "type": "string"
                    },
                    {
                        "name": "fee",
                        "type": "Fee"
                    },
                    {
                        "name": "memo",
                        "type": "string"
                    },
                    {
                        "name": "msgs",
                        "type": "Msg[]"
                    },
                    {
                        "name": "sequence",
                        "type": "string"
                    }
                ]
            }
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();
        // println!("hash: {:?}", hex::encode(&hash[..]));
    }

    #[test]
    fn test_perp_parse() {
        let json = serde_json::json!({
            "types": {
                "Order": [
                    {
                        "name": "sender",
                        "type": "bytes32"
                    },
                    {
                        "name": "priceX18",
                        "type": "int128"
                    },
                    {
                        "name": "amount",
                        "type": "int128"
                    },
                    {
                        "name": "expiration",
                        "type": "uint64"
                    },
                    {
                        "name": "nonce",
                        "type": "uint64"
                    }
                ],
                "EIP712Domain": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "version",
                        "type": "string"
                    },
                    {
                        "name": "chainId",
                        "type": "uint256"
                    },
                    {
                        "name": "verifyingContract",
                        "type": "address"
                    }
                ]
            },
            "primaryType": "Order",
            "domain": {
                "name": "Vertex",
                "version": "0.0.1",
                "chainId": "0x13e31",
                "verifyingContract": "0x8288b2a21fea95b2594cdefb4553bb223697e80b"
            },
            "message": {
                "sender": "0x49ab56b91fc982fd6ec1ec7bb87d74efa6da30ab64656661756c740000000000",
                "priceX18": "3867500000000000000000",
                "amount": "-10000000000000000",
                "expiration": "11529216762868464034",
                "nonce": "1800195364132749377"
            }
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            hex::encode(&hash[..]),
            "3ffb3216a4dd87005feef7fa50a2f42372653c31d0b2828e8b51fb03b1424106",
        )
    }

    #[test]
    fn test_hash_permit2_typed_message_with_data() {
        let json = serde_json::json!( {
          "types": {
            "EIP712Domain": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              }
            ],
            "Message": []
          },
          "primaryType": "EIP712Domain",
          "domain": {
            "name": "Permit2",
            "chainId": "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000"
          },
          "message": {}
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();

        let domain_separator = typed_data.domain.separator(Some(&typed_data.types));
        assert_eq!(
            "a5ed1342e96a6ee3ea989ce263f510f5423d3be0fc366e15ae46811ab03641e5",
            hex::encode(domain_separator)
        );
    }

    #[test]
    fn test_hash_permit2_typed_message_with_permit_single_data() {
        let json = serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "chainId",
                        "type": "uint256"
                    },
                    {
                        "name": "verifyingContract",
                        "type": "address"
                    }
                ],
                "PermitDetails": [
                    {
                        "name": "token",
                        "type": "address"
                    },
                    {
                        "name": "amount",
                        "type": "uint160"
                    },
                    {
                        "name": "expiration",
                        "type": "uint48"
                    },
                    {
                        "name": "nonce",
                        "type": "uint48"
                    }
                ],
                "PermitSingle": [
                    {
                        "name": "details",
                        "type": "PermitDetails"
                    },
                    {
                        "name": "spender",
                        "type": "address"
                    },
                    {
                        "name": "sigDeadline",
                        "type": "uint256"
                    }
                ]
            },
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2",
                "chainId": "1",
                "verifyingContract": "0x0000000000000000000000000000000000000000"
            },
            "message": {
                "details": {
                    "token": "0x0000000000000000000000000000000000000000",
                    "amount": "0",
                    "expiration": "0",
                    "nonce": "0"
                },
                "spender": "0x0000000000000000000000000000000000000000",
                "sigDeadline": "0"
            }
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "d47437bffdbc4d123a2165feb6ca646b8700c038622ce304f84e9048bc744f36",
            hex::encode(&hash[..])
        );
    }
    #[test]
    fn test_hash_permit2_batch_typed_message_with_data() {
        let json = serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "chainId",
                        "type": "uint256"
                    },
                    {
                        "name": "verifyingContract",
                        "type": "address"
                    }
                ],
                "PermitDetails": [
                    {
                        "name": "token",
                        "type": "address"
                    },
                    {
                        "name": "amount",
                        "type": "uint160"
                    },
                    {
                        "name": "expiration",
                        "type": "uint48"
                    },
                    {
                        "name": "nonce",
                        "type": "uint48"
                    }
                ],
                "PermitBatch": [
                    {
                        "name": "details",
                        "type": "PermitDetails[]"
                    },
                    {
                        "name": "spender",
                        "type": "address"
                    },
                    {
                        "name": "sigDeadline",
                        "type": "uint256"
                    }
                ]
            },
            "primaryType": "PermitBatch",
            "domain": {
                "name": "Permit2",
                "chainId": "1",
                "verifyingContract": "0x0000000000000000000000000000000000000000"
            },
            "message": {
                "details": [
                    {
                        "token": "0x0000000000000000000000000000000000000000",
                        "amount": "0",
                        "expiration": "0",
                        "nonce": "0"
                    }
                ],
                "spender": "0x0000000000000000000000000000000000000000",
                "sigDeadline": "0"
            }
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            "49642ada5f77eb9458f8265eb01fed2684c2f25d50534fea3efdf2cf395deb2f",
            hex::encode(&hash[..])
        );
    }

    #[test]
    fn new_typed_data() {
        let mut types: BTreeMap<String, Vec<Eip712DomainType>> = BTreeMap::new();
        let mut message: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        message.insert(
            "sender".to_string(),
            serde_json::from_value(serde_json::Value::String(
                "0x49ab56b91fc982fd6ec1ec7bb87d74efa6da30ab64656661756c740000000000".to_string(),
            ))
            .unwrap(),
        );
        message.insert(
            "priceX18".to_string(),
            serde_json::from_value(serde_json::Value::String(
                "3867500000000000000000".to_string(),
            ))
            .unwrap(),
        );

        message.insert(
            "amount".to_string(),
            serde_json::from_value(serde_json::Value::String("-10000000000000000".to_string()))
                .unwrap(),
        );
        message.insert(
            "expiration".to_string(),
            serde_json::from_value(serde_json::Value::String(
                "11529216762868464034".to_string(),
            ))
            .unwrap(),
        );
        message.insert(
            "nonce".to_string(),
            serde_json::from_value(serde_json::Value::String("1800195364132749377".to_string()))
                .unwrap(),
        );
        types.insert(
            "Order".to_string(),
            vec![
                Eip712DomainType {
                    name: "sender".to_string(),
                    r#type: "bytes32".to_string(),
                },
                Eip712DomainType {
                    name: "priceX18".to_string(),
                    r#type: "int128".to_string(),
                },
                Eip712DomainType {
                    name: "amount".to_string(),
                    r#type: "int128".to_string(),
                },
                Eip712DomainType {
                    name: "expiration".to_string(),
                    r#type: "uint64".to_string(),
                },
                Eip712DomainType {
                    name: "nonce".to_string(),
                    r#type: "uint64".to_string(),
                },
            ],
        );
        types.insert(
            "EIP712Domain".to_string(),
            vec![
                Eip712DomainType {
                    name: "name".to_string(),
                    r#type: "string".to_string(),
                },
                Eip712DomainType {
                    name: "version".to_string(),
                    r#type: "string".to_string(),
                },
                Eip712DomainType {
                    name: "chainId".to_string(),
                    r#type: "uint256".to_string(),
                },
                Eip712DomainType {
                    name: "verifyingContract".to_string(),
                    r#type: "address".to_string(),
                },
            ],
        );
        let typed_data = TypedData {
            domain: EIP712Domain {
                name: Some("Vertex".to_string()),
                version: Some("0.0.1".to_string()),
                chain_id: Some(U256::from(81457)),
                verifying_contract: Some("0x8288b2a21fea95b2594cdefb4553bb223697e80b".to_string()),
                salt: None,
            },
            types,
            primary_type: "Order".to_string(),
            message,
        };
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            hex::encode(&hash[..]),
            "3ffb3216a4dd87005feef7fa50a2f42372653c31d0b2828e8b51fb03b1424106",
        )
    }

    #[test]
    fn test_new_uniswap_permit2_single() {
        let json = serde_json::json!(
            {
                "domain": {
                    "name": "Permit2",
                    "chainId": "0x1",
                    "verifyingContract": "0x000000000022d473030f116ddee9f6b43ac78ba3"
                },
                "types": {
                    "EIP712Domain": [
                        {
                            "name": "name",
                            "type": "string"
                        },
                        {
                            "name": "chainId",
                            "type": "uint256"
                        },
                        {
                            "name": "verifyingContract",
                            "type": "address"
                        }
                    ],
                    "PermitDetails": [
                        {
                            "name": "token",
                            "type": "address"
                        },
                        {
                            "name": "amount",
                            "type": "uint160"
                        },
                        {
                            "name": "expiration",
                            "type": "uint48"
                        },
                        {
                            "name": "nonce",
                            "type": "uint48"
                        }
                    ],
                    "PermitSingle": [
                        {
                            "name": "details",
                            "type": "PermitDetails"
                        },
                        {
                            "name": "spender",
                            "type": "address"
                        },
                        {
                            "name": "sigDeadline",
                            "type": "uint256"
                        }
                    ]
                },
                "primaryType": "PermitSingle",
                "message": {
                    "details": {
                        "amount": "1461501637330902918203684832716283019655932542975",
                        "expiration": "1734011793",
                        "nonce": "0",
                        "token": "0xe957ea0b072910f508dd2009f4acb7238c308e29"
                    },
                    "sigDeadline": "1731421593",
                    "spender": "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad"
                }
            }
        );

        let typed_data: TypedData = serde_json::from_value(json).unwrap();

        let type_hash = hash_type(&typed_data.primary_type, &typed_data.types).unwrap();
        assert_eq!(
            "f3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d0",
            hex::encode(type_hash)
        );
        let hash = typed_data.encode_eip712().unwrap();
        assert_eq!(
            hex::encode(&hash[..]),
            "d2e7a265a8e9ecb533e846309a14f0c034fee3e4ecb3f985755dae05b7a4804d",
        );
    }
}
