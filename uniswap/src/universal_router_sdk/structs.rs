use alloy::primitives::{Address, Bytes, U256};
use anyhow::Result;
use std::str::FromStr;

use super::universal_router_commands::UniswapV3UniversalRouterCommand;

pub struct DecodeExecuteResult {
    pub commands: Bytes,
    pub inputs: Vec<Bytes>,
    pub deadline: U256,
}

impl ToString for DecodeExecuteResult {
    fn to_string(&self) -> String {
        // loop the commands
        let commands: Vec<u8> = self.commands.to_vec();
        let mut res = String::new();
        // for each command
        for (i, command) in commands.iter().enumerate() {
            if let Ok(cmd) = UniswapV3UniversalRouterCommand::try_from(*command) {
                // decode the command
                let data = self.inputs[i].to_vec();
                res.push_str(&cmd.decode(&data));
            }
        }
        res
    }
}

#[derive(Debug, Clone, Default)]
pub struct WarpAddress(Address);

impl From<&str> for WarpAddress {
    fn from(value: &str) -> Self {
        Self(Address::from_str(value).unwrap())
    }
}

impl TryInto<Address> for WarpAddress {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<Address> {
        Ok(self.0)
    }
}
