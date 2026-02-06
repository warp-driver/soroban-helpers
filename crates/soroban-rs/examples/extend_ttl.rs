//! Example demonstrating how to extend the TTL of a deployed contract
//!
//! This example shows:
//! 1. Loading environment configuration
//! 2. Setting up an account
//! 3. Deploying a contract
//! 4. Extending the contract's TTL

use dotenv::from_path;
use ed25519_dalek::SigningKey;
use soroban_rs::{Account, Contract, Env, EnvConfigs, IntoScVal, Signer};
use std::{env, error::Error, path::Path};
use stellar_strkey::ed25519::PrivateKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    from_path(Path::new("examples/.env")).ok();

    let private_key_str =
        env::var("SOROBAN_PRIVATE_KEY_1").expect("SOROBAN_PRIVATE_KEY must be set");
    let private_key = PrivateKey::from_string(&private_key_str)?;
    let signing_key = SigningKey::from_bytes(&private_key.0);

    let configs = EnvConfigs {
        rpc_url: "https://soroban-testnet.stellar.org".to_string(),
        network_passphrase: "Test SDF Network ; September 2015".to_string(),
    };
    let env = Env::new(configs)?;

    let mut account = Account::single(Signer::new(signing_key));

    // Deploy contract
    let contract = Contract::new("./fixtures/soroban-helpers-example.wasm", None)?;
    let deployed = contract
        .deploy(&env, &mut account, Some(vec![(42_u32).into_val()]))
        .await?;

    println!("Contract deployed: {:?}", deployed.contract_id());

    // Get current ledger to calculate extend_to value
    // In production, you'd want to extend to current_ledger + desired_lifetime
    let extend_to = 2_000_000; // Example: extend to ledger 2 million

    println!("Extending contract TTL to ledger: {}", extend_to);

    // Extend the contract's TTL
    deployed.extend_ttl(extend_to, &env, &mut account).await?;

    println!("Contract TTL successfully extended!");

    Ok(())
}
