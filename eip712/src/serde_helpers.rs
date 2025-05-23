//! Some convenient serde helpers

use core::{
    borrow::Borrow,
    convert::{TryFrom, TryInto},
    str::FromStr,
};
use cryptoxide::digest::Digest;
use cryptoxide::sha3::Keccak256;
use ethabi::ethereum_types::{U256, U64};
use serde::{Deserialize, Deserializer};
use serde_json;
use std::string::ToString;
use std::{borrow::ToOwned, string::String};

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.input(input);
    let mut output = [0u8; 32];
    hasher.result(&mut output);
    output
}
/// Helper type to parse both `u64` and `U256`
#[derive(Copy, Clone, Deserialize)]
#[serde(untagged)]
pub enum Numeric {
    U256(U256),
    Num(u64),
}

impl From<Numeric> for U256 {
    fn from(n: Numeric) -> U256 {
        match n {
            Numeric::U256(n) => n,
            Numeric::Num(n) => U256::from(n),
        }
    }
}

impl FromStr for Numeric {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(val) = s.parse::<u128>() {
            Ok(Numeric::U256(val.into()))
        } else if s.starts_with("0x") {
            U256::from_str(s)
                .map(Numeric::U256)
                .map_err(|err| err.to_string())
        } else {
            U256::from_dec_str(s)
                .map(Numeric::U256)
                .map_err(|err| err.to_string())
        }
    }
}

/// Helper type to parse numeric strings, `u64` and `U256`
#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum StringifiedNumeric {
    String(String),
    U256(U256),
    Num(serde_json::Number),
}

impl TryFrom<StringifiedNumeric> for i128 {
    type Error = String;

    fn try_from(value: StringifiedNumeric) -> Result<Self, Self::Error> {
        match value {
            StringifiedNumeric::U256(n) => Ok(n.as_u128() as i128),
            StringifiedNumeric::Num(n) => Ok(n.as_i64().unwrap() as i128),
            StringifiedNumeric::String(s) => {
                if let Ok(val) = s.parse::<i128>() {
                    Ok(val)
                } else if s.starts_with("0x") {
                    U256::from_str(&s)
                        .map(|n| n.as_u128() as i128)
                        .map_err(|err| err.to_string())
                } else {
                    U256::from_dec_str(&s)
                        .map(|n| n.as_u128() as i128)
                        .map_err(|err| err.to_string())
                }
            }
        }
    }
}

impl TryFrom<StringifiedNumeric> for U256 {
    type Error = String;

    fn try_from(value: StringifiedNumeric) -> Result<Self, Self::Error> {
        match value {
            StringifiedNumeric::U256(n) => Ok(n),
            StringifiedNumeric::Num(n) => {
                Ok(U256::from_dec_str(&n.to_string()).map_err(|err| err.to_string())?)
            }
            StringifiedNumeric::String(s) => {
                if let Ok(val) = s.parse::<u128>() {
                    Ok(val.into())
                } else if s.starts_with("0x") {
                    U256::from_str(&s).map_err(|err| err.to_string())
                } else {
                    U256::from_dec_str(&s).map_err(|err| err.to_string())
                }
            }
        }
    }
}

impl TryFrom<StringifiedNumeric> for [u8; 32] {
    type Error = String;

    fn try_from(value: StringifiedNumeric) -> Result<Self, Self::Error> {
        let u256_value = U256::try_from(value)?;
        let mut be_bytes = [0u8; 32];
        u256_value.to_big_endian(&mut be_bytes);
        Ok(be_bytes)
    }
}

impl TryFrom<StringifiedNumeric> for U64 {
    type Error = String;

    fn try_from(value: StringifiedNumeric) -> Result<Self, Self::Error> {
        let value = U256::try_from(value)?;
        let mut be_bytes = [0u8; 32];
        value.to_big_endian(&mut be_bytes);
        U64::try_from(&be_bytes[value.leading_zeros() as usize / 8..])
            .map_err(|err| err.to_string())
    }
}

/// Supports parsing numbers as strings
///
/// See <https://github.com/gakonst/ethers-rs/issues/1507>
pub fn deserialize_stringified_numeric<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let num = StringifiedNumeric::deserialize(deserializer)?;
    num.try_into().map_err(serde::de::Error::custom)
}

/// Supports parsing numbers as strings
///
/// See <https://github.com/gakonst/ethers-rs/issues/1507>
pub fn deserialize_stringified_numeric_opt<'de, D>(
    deserializer: D,
) -> Result<Option<U256>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Some(num) = Option::<StringifiedNumeric>::deserialize(deserializer)? {
        num.try_into().map(Some).map_err(serde::de::Error::custom)
    } else {
        Ok(None)
    }
}

pub fn deserialize_stringified_array_opt<'de, D>(
    deserializer: D,
) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Some(num) = Option::<StringifiedNumeric>::deserialize(deserializer)? {
        num.try_into().map(Some).map_err(serde::de::Error::custom)
    } else {
        Ok(None)
    }
}

pub fn deserialize_salt_opt<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Some(num) = Option::<StringifiedNumeric>::deserialize(deserializer)? {
        if let StringifiedNumeric::String(s) = num.borrow() {
            if !s.starts_with("0x") {
                return Ok(Some(U256::from(keccak256(s.as_bytes())).into()));
            }
        }
        num.try_into().map(Some).map_err(serde::de::Error::custom)
    } else {
        Ok(None)
    }
}

/// Supports parsing ethereum-types U64
///
/// See <https://github.com/gakonst/ethers-rs/issues/1507>
pub fn deserialize_stringified_eth_u64<'de, D>(deserializer: D) -> Result<U64, D::Error>
where
    D: Deserializer<'de>,
{
    let num = StringifiedNumeric::deserialize(deserializer)?;
    num.try_into().map_err(serde::de::Error::custom)
}

/// Supports parsing ethereum-types `Option<U64>`
///
/// See <https://github.com/gakonst/ethers-rs/issues/1507>
pub fn deserialize_stringified_eth_u64_opt<'de, D>(deserializer: D) -> Result<Option<U64>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Some(num) = Option::<StringifiedNumeric>::deserialize(deserializer)? {
        let num: U64 = num.try_into().map_err(serde::de::Error::custom)?;
        Ok(Some(num))
    } else {
        Ok(None)
    }
}

/// Supports parsing u64
///
/// See <https://github.com/gakonst/ethers-rs/issues/1507>
pub fn deserialize_stringified_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let num = StringifiedNumeric::deserialize(deserializer)?;
    let num: U256 = num.try_into().map_err(serde::de::Error::custom)?;
    num.try_into().map_err(serde::de::Error::custom)
}

/// Supports parsing u64
///
/// See <https://github.com/gakonst/ethers-rs/issues/1507>
pub fn deserialize_stringified_u64_opt<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Some(num) = Option::<StringifiedNumeric>::deserialize(deserializer)? {
        let num: U256 = num.try_into().map_err(serde::de::Error::custom)?;
        let num: u64 = num.try_into().map_err(serde::de::Error::custom)?;
        Ok(Some(num))
    } else {
        Ok(None)
    }
}

/// Helper type to deserialize sequence of numbers
#[derive(Deserialize)]
#[serde(untagged)]
pub enum NumericSeq {
    Seq([Numeric; 1]),
    U256(U256),
    Num(u64),
}

/// Deserializes a number from hex or int
pub fn deserialize_number<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    Numeric::deserialize(deserializer).map(Into::into)
}

/// Deserializes a number from hex or int, but optionally
pub fn deserialize_number_opt<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
where
    D: Deserializer<'de>,
{
    let num = match Option::<Numeric>::deserialize(deserializer)? {
        Some(Numeric::U256(n)) => Some(n),
        Some(Numeric::Num(n)) => Some(U256::from(n)),
        _ => None,
    };

    Ok(num)
}

/// Deserializes single integer params: `1, [1], ["0x01"]`
pub fn deserialize_number_seq<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let num = match NumericSeq::deserialize(deserializer)? {
        NumericSeq::Seq(seq) => seq[0].into(),
        NumericSeq::U256(n) => n,
        NumericSeq::Num(n) => U256::from(n),
    };

    Ok(num)
}
