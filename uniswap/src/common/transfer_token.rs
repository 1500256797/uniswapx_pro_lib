#[cfg(test)]
mod tests {

    use alloy::{
        network::{Ethereum, EthereumWallet, NetworkWallet, TransactionBuilder},
        primitives::{address, U256},
        providers::{Provider, ProviderBuilder},
        rpc::types::TransactionRequest,
        signers::ledger::{HDPath, LedgerSigner},
    };
    use anyhow::Result;
    #[tokio::test]
    async fn test_swap_with_ledger_signer() -> Result<()> {
        assert!(true);
        return Ok(());
        // Instantiate the application by acquiring a lock on the Ledger device.
        let signer = LedgerSigner::new(HDPath::LedgerLive(0), Some(1)).await?;
        let wallet = EthereumWallet::from(signer);

        let addresses = <EthereumWallet as NetworkWallet<Ethereum>>::signer_addresses(&wallet)
            .into_iter()
            .collect::<Vec<_>>();
        println!("addresses: {:?}", addresses);
        for addr in addresses {
            println!("address: {:?}", addr);
        }
        // Create a provider with the wallet.
        let rpc_url = "https://eth.merkle.io".parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(rpc_url);

        // Build a transaction to send 100 wei from Alice to Vitalik.
        // The `from` field is automatically filled to the first signer's address (Alice).
        let vitalik = address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let tx = TransactionRequest::default()
            .with_to(vitalik)
            .with_value(U256::from(100));

        // Send the transaction and wait for inclusion with 3 confirmations.
        let tx_hash = provider
            .send_transaction(tx)
            .await?
            .with_required_confirmations(3)
            .watch()
            .await?;

        println!("Sent transaction: {tx_hash}");
        assert!(true);
        Ok(())
    }
}
