//! # Signing `Address`-credential authorization entries
//!
//! Soroban has a two-credential authorization model. When a contract calls
//! `Address::require_auth`, simulation returns a [`SorobanAuthorizationEntry`]
//! whose credential is either:
//!
//! - [`SorobanCredentials::SourceAccount`] — covered by the transaction's own
//!   signature (handled by the normal build/sign path), or
//! - [`SorobanCredentials::Address`] — requires a *separate* signature from the
//!   named address, supplied on the entry itself (the `authorizeEntry` flow).
//!
//! The plain [`crate::simulate_transaction`] path only handles the
//! `SourceAccount` case, so it cannot drive an invocation whose required signer
//! is a **contract account** (a `C…` address with a custom `__check_auth`) — a
//! multisig / smart wallet. This module fills that gap:
//!
//! - [`sign_auth_entry`] signs one simulation-returned `Address` entry on behalf
//!   of a smart account, and
//! - [`simulate_transaction_with_auth`] runs the full dance: simulate, sign +
//!   attach the entries, then re-simulate so the footprint and resource fee
//!   account for `__check_auth`.
//!
//! ## Signature format
//!
//! For a contract account the `signature` ScVal is contract-defined. These
//! helpers produce the common ed25519 smart-account convention: a `Vec` of
//! `{ public_key: BytesN<32>, signature: BytesN<64> }` structs, one per signer,
//! sorted by public key. This matches the smart account used by this repo's
//! `warpdrive-multisig-account` fixture and the OpenZeppelin-style smart
//! accounts it mirrors. Contracts whose `__check_auth` expects a different
//! encoding are not covered.
//!
//! ## Example
//!
//! ```rust,no_run
//! use wasi_soroban_rs::{
//!     simulate_transaction_with_auth, Account, ContractId, Env, Operations, Signer,
//!     TransactionBuilder,
//! };
//! use wasi_soroban_rs::xdr::ScAddress;
//!
//! async fn invoke_via_multisig(
//!     env: Env,
//!     mut source: Account,        // pays the fee and signs as tx source
//!     smart_account: ScAddress,   // the C… contract account that must authorize
//!     signers: Vec<Signer>,       // its ed25519 signing policy
//!     contract: ContractId,       // the contract being invoked
//!     valid_until_ledger: u32,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let op = Operations::invoke_contract(&contract, "transfer", vec![])?;
//!     let tx = TransactionBuilder::new(&source, &env)
//!         .add_operation(op)
//!         .build()
//!         .await?;
//!
//!     // Sign the smart account's Address auth and re-price for `__check_auth`.
//!     let tx =
//!         simulate_transaction_with_auth(tx, &env, &smart_account, &signers, valid_until_ledger)
//!             .await?;
//!
//!     // The source account still signs as the fee payer, then submit.
//!     let signed = source.sign_transaction(&tx, &env.network_id())?;
//!     env.send_transaction(&signed).await?;
//!     Ok(())
//! }
//! ```
use crate::{
    crypto, error::SorobanHelperError, transaction::DEFAULT_TRANSACTION_FEES, Env, Signer,
};
use stellar_xdr::curr::{
    Hash, InvokeHostFunctionOp, Operation, OperationBody, ScAddress, ScBytes, ScMap, ScMapEntry,
    ScSymbol, ScVal, ScVec, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanCredentials, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
    VecM,
};

/// Extra fee margin (in stroops) added on top of the base fee and the simulated
/// `min_resource_fee` when re-pricing an auth-bearing transaction. A small
/// cushion against the resource estimate being slightly under what submission
/// charges (which would otherwise surface as `ResourceLimitExceeded`).
const AUTH_FEE_BUFFER: u64 = 100_000;

/// Builds the smart-account signature ScVal: a `Vec` of
/// `{ public_key, signature }` structs, one per signer, signing `digest` with
/// each. Entries are sorted by public key.
fn multisig_signature_scval(
    signers: &[Signer],
    digest: &[u8; 32],
) -> Result<ScVal, SorobanHelperError> {
    let mut signed: Vec<([u8; 32], ScVal)> = signers
        .iter()
        .map(|signer| {
            let public_key = signer.public_key().0;
            let signature = signer.sign_payload(digest);

            // A `#[contracttype]` struct is an ScMap keyed by its field-name
            // symbols, in sorted order. "public_key" < "signature", so emit
            // them in that order.
            let map = ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into()?)),
                        val: ScVal::Bytes(ScBytes(public_key.to_vec().try_into()?)),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into()?)),
                        val: ScVal::Bytes(ScBytes(signature.to_vec().try_into()?)),
                    },
                ]
                .try_into()?,
            );

            Ok((public_key, ScVal::Map(Some(map))))
        })
        .collect::<Result<_, SorobanHelperError>>()?;

    signed.sort_by(|(a, _), (b, _)| a.cmp(b));

    let entries: Vec<ScVal> = signed.into_iter().map(|(_, scval)| scval).collect();
    Ok(ScVal::Vec(Some(ScVec(entries.try_into()?))))
}

/// Signs a simulation-returned authorization entry on behalf of `smart_account`.
///
/// Mirrors `authorizeEntry` from the JS/Python SDKs. If `entry` carries an
/// [`SorobanCredentials::Address`] credential for `smart_account`, its
/// `signature_expiration_ledger` and `signature` are populated by signing the
/// `HashIdPreimage::SorobanAuthorization` digest with `signers` using the
/// `Vec<{public_key, signature}>` convention.
///
/// Any other entry passes through **unchanged**: a `SourceAccount` credential
/// (the transaction signature covers it) or an `Address` credential for a
/// *different* address (the caller signs that some other way). Callers that
/// need every `Address` entry signed should check for left-over unsigned
/// entries — [`simulate_transaction_with_auth`] does this.
///
/// # Parameters
///
/// * `entry` - The entry returned by simulation
/// * `smart_account` - The address whose authorization `signers` can provide
/// * `signers` - The ed25519 signers of `smart_account`'s policy
/// * `valid_until_ledger` - Ledger after which the signature expires
/// * `network_id` - The network ID hash (see [`crate::Env::network_id`])
///
/// # Errors
///
/// Returns `SorobanHelperError::XdrEncodingFailed` if the preimage or signature
/// cannot be encoded.
pub fn sign_auth_entry(
    entry: &SorobanAuthorizationEntry,
    smart_account: &ScAddress,
    signers: &[Signer],
    valid_until_ledger: u32,
    network_id: &Hash,
) -> Result<SorobanAuthorizationEntry, SorobanHelperError> {
    let SorobanCredentials::Address(creds) = &entry.credentials else {
        return Ok(entry.clone());
    };
    if &creds.address != smart_account {
        return Ok(entry.clone());
    }

    let digest = crypto::auth_preimage_hash(
        network_id,
        creds.nonce,
        valid_until_ledger,
        &entry.root_invocation,
    )?;
    let signature = multisig_signature_scval(signers, &digest.0)?;

    Ok(SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: creds.address.clone(),
            nonce: creds.nonce,
            signature_expiration_ledger: valid_until_ledger,
            signature,
        }),
        root_invocation: entry.root_invocation.clone(),
    })
}

/// Wraps a transaction in an envelope with no signatures, for simulation.
fn unsigned_envelope(tx: &Transaction) -> TransactionEnvelope {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: VecM::default(),
    })
}

/// Simulates `tx`, signs the `Address` authorization it requires on behalf of
/// `smart_account`, attaches the signed entries, and re-simulates so the
/// footprint and resource fee account for `__check_auth`.
///
/// This is the `Address`-credential counterpart to [`crate::simulate_transaction`].
/// The returned transaction is ready for the **source account** to sign (as the
/// fee payer) and submit — this function does neither.
///
/// The two passes are both necessary:
/// 1. the *recording* pass discovers which entries the call requires (their
///    nonces and invocation trees), and
/// 2. the *enforce* pass — run with the signed auth attached — executes
///    `__check_auth`, so the returned `transaction_data` and `min_resource_fee`
///    cover the account's signature verification. Submitting with only the
///    recording pass's fee hits `ResourceLimitExceeded`.
///
/// # Parameters
///
/// * `tx` - A built (unsigned) transaction whose invoke-host-function ops need
///   `smart_account`'s authorization
/// * `env` - The environment to simulate against
/// * `smart_account` - The contract/classic account whose auth is required
/// * `signers` - The ed25519 signers of `smart_account`'s policy
/// * `valid_until_ledger` - Ledger after which the signatures expire
///
/// # Errors
///
/// Returns:
/// - `SorobanHelperError::TransactionSimulationFailed` if either simulation
///   pass reports an error or returns undecodable results,
/// - `SorobanHelperError::NotSupported` if an entry requires a signature from
///   an address other than `smart_account` (no signer available for it),
/// - `SorobanHelperError::XdrEncodingFailed` / `InvalidArgument` on encoding or
///   fee-overflow failures.
pub async fn simulate_transaction_with_auth(
    mut tx: Transaction,
    env: &Env,
    smart_account: &ScAddress,
    signers: &[Signer],
    valid_until_ledger: u32,
) -> Result<Transaction, SorobanHelperError> {
    let network_id = env.network_id();

    // Recording pass: discover the auth entries the call requires.
    let simulation = env.simulate_transaction(&unsigned_envelope(&tx)).await?;
    if let Some(err) = simulation.error {
        return Err(SorobanHelperError::TransactionSimulationFailed(err));
    }
    let results = simulation.results().map_err(|e| {
        SorobanHelperError::TransactionSimulationFailed(format!(
            "failed to decode simulation results: {e}"
        ))
    })?;

    // Sign and attach the auth for each invoke-host-function op, in order.
    let mut ops: Vec<Operation> = tx.operations.iter().cloned().collect();
    let mut result_idx = 0usize;
    for op in ops.iter_mut() {
        let OperationBody::InvokeHostFunction(InvokeHostFunctionOp { auth, .. }) = &mut op.body
        else {
            continue;
        };
        let result = results.get(result_idx).ok_or_else(|| {
            SorobanHelperError::TransactionSimulationFailed(
                "simulation result count does not match operations".to_string(),
            )
        })?;
        result_idx += 1;

        let mut signed = Vec::with_capacity(result.auth.len());
        for entry in &result.auth {
            let s = sign_auth_entry(
                entry,
                smart_account,
                signers,
                valid_until_ledger,
                &network_id,
            )?;
            // Any Address entry we couldn't sign (a different address) keeps the
            // void signature simulation returned. Fail fast with the address
            // that still needs an external signature rather than submitting an
            // unauthorized transaction.
            if let SorobanCredentials::Address(c) = &s.credentials {
                if matches!(c.signature, ScVal::Void) {
                    return Err(SorobanHelperError::NotSupported(format!(
                        "auth entry needs an external signature from {}; only {} was provided",
                        c.address, smart_account
                    )));
                }
            }
            signed.push(s);
        }
        *auth = signed.try_into()?;
    }
    tx.operations = ops.try_into()?;

    // Enforce pass: with the auth attached, the footprint + fee now cover
    // `__check_auth`.
    let simulation = env.simulate_transaction(&unsigned_envelope(&tx)).await?;
    if let Some(err) = simulation.error {
        return Err(SorobanHelperError::TransactionSimulationFailed(err));
    }

    tx.ext = TransactionExt::V1(simulation.transaction_data().map_err(|e| {
        SorobanHelperError::TransactionFailed(format!("failed to get transaction data: {e}"))
    })?);
    tx.fee = u32::try_from(
        tx.operations.len() as u64 * DEFAULT_TRANSACTION_FEES as u64
            + simulation.min_resource_fee
            + AUTH_FEE_BUFFER,
    )
    .map_err(|_| SorobanHelperError::InvalidArgument("fee overflows u32".to_string()))?;

    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::mock_env;
    use crate::operation::Operations;
    use crate::TransactionBuilder;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use stellar_xdr::curr::{
        ContractId, InvokeContractArgs, LedgerFootprint, Limits, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanResources, SorobanTransactionData,
        SorobanTransactionDataExt, WriteXdr,
    };
    use wasi_stellar_rpc_client::{SimulateHostFunctionResultRaw, SimulateTransactionResponse};

    const NETWORK_ID: Hash = Hash([0u8; 32]);

    fn contract_address(byte: u8) -> ScAddress {
        ScAddress::Contract(ContractId(Hash([byte; 32])))
    }

    /// A minimal `transfer`-shaped invocation tree to authorize.
    fn invocation(target: &ScAddress) -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: target.clone(),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        }
    }

    fn address_entry(address: &ScAddress, nonce: i64) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: address.clone(),
                nonce,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation(address),
        }
    }

    #[test]
    fn source_account_entry_passes_through() {
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: invocation(&contract_address(1)),
        };
        let signer = Signer::from(&[1u8; 32]);
        let signed =
            sign_auth_entry(&entry, &contract_address(1), &[signer], 100, &NETWORK_ID).unwrap();
        assert_eq!(signed, entry);
    }

    #[test]
    fn address_entry_for_other_address_passes_through() {
        let entry = address_entry(&contract_address(7), 42);
        let signer = Signer::from(&[1u8; 32]);
        // We hold a signer for a *different* smart account.
        let signed =
            sign_auth_entry(&entry, &contract_address(9), &[signer], 100, &NETWORK_ID).unwrap();
        assert_eq!(signed, entry);
    }

    #[test]
    fn signs_matching_address_entry_with_verifiable_signatures() {
        let smart_account = contract_address(7);
        let nonce = 0xC0FFEE_i64;
        let expiration = 10_000_u32;
        let entry = address_entry(&smart_account, nonce);

        let signers = [Signer::from(&[0xA1; 32]), Signer::from(&[0xB2; 32])];
        let signed =
            sign_auth_entry(&entry, &smart_account, &signers, expiration, &NETWORK_ID).unwrap();

        let SorobanCredentials::Address(creds) = &signed.credentials else {
            panic!("expected Address credentials");
        };
        assert_eq!(creds.address, smart_account);
        assert_eq!(creds.nonce, nonce);
        assert_eq!(creds.signature_expiration_ledger, expiration);

        // The digest the host recomputes and feeds to `__check_auth`.
        let digest =
            crypto::auth_preimage_hash(&NETWORK_ID, nonce, expiration, &entry.root_invocation)
                .unwrap()
                .0;

        let ScVal::Vec(Some(ScVec(sig_vec))) = &creds.signature else {
            panic!("expected the signature to be a Vec");
        };
        assert_eq!(sig_vec.len(), 2);

        // Each element is a {public_key, signature} struct whose signature
        // verifies over `digest` — exactly what the contract's ed25519_verify
        // checks. Collect the public keys to assert the sort order too.
        let mut seen_keys: Vec<[u8; 32]> = Vec::new();
        for element in sig_vec.iter() {
            let ScVal::Map(Some(map)) = element else {
                panic!("expected a map");
            };
            assert_eq!(map.0.len(), 2);
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol("public_key".try_into().unwrap()))
            );
            assert_eq!(
                map.0[1].key,
                ScVal::Symbol(ScSymbol("signature".try_into().unwrap()))
            );

            let ScVal::Bytes(pk) = &map.0[0].val else {
                panic!("public_key is not bytes");
            };
            let ScVal::Bytes(sig) = &map.0[1].val else {
                panic!("signature is not bytes");
            };
            let pk: [u8; 32] = pk.0.as_slice().try_into().unwrap();
            let sig: [u8; 64] = sig.0.as_slice().try_into().unwrap();

            VerifyingKey::from_bytes(&pk)
                .unwrap()
                .verify(&digest, &Signature::from_bytes(&sig))
                .expect("signature must verify over the auth preimage digest");
            seen_keys.push(pk);
        }

        // Sorted by public key, regardless of the order signers were supplied.
        let mut expected = seen_keys.clone();
        expected.sort();
        assert_eq!(seen_keys, expected);
    }

    /// Builds a simulation response carrying `entries` as the (single) op's auth,
    /// plus a decodable empty `transaction_data` so the enforce pass succeeds.
    fn sim_response(
        entries: &[SorobanAuthorizationEntry],
        min_resource_fee: u64,
    ) -> SimulateTransactionResponse {
        let auth: Vec<String> = entries
            .iter()
            .map(|e| e.to_xdr_base64(Limits::none()).unwrap())
            .collect();
        let tx_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: VecM::default(),
                    read_write: VecM::default(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };
        SimulateTransactionResponse {
            min_resource_fee,
            results: vec![SimulateHostFunctionResultRaw {
                auth,
                xdr: ScVal::Void.to_xdr_base64(Limits::none()).unwrap(),
            }],
            transaction_data: tx_data.to_xdr_base64(Limits::none()).unwrap(),
            ..Default::default()
        }
    }

    async fn build_invoke_tx(env: &Env) -> Transaction {
        let source = crate::Account::single(Signer::from(&[3u8; 32]));
        let contract = stellar_strkey::Contract([5u8; 32]);
        let op = Operations::invoke_contract(&contract, "transfer", vec![]).unwrap();
        TransactionBuilder::new(&source, env)
            .add_operation(op)
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn simulate_with_auth_signs_attaches_and_reprices() {
        let smart_account = contract_address(7);
        let min_resource_fee = 4242;
        let response = sim_response(&[address_entry(&smart_account, 1)], min_resource_fee);
        let env = mock_env(None, Some(Ok(response)), None);

        let tx = build_invoke_tx(&env).await;
        let signers = [Signer::from(&[0xA1; 32]), Signer::from(&[0xB2; 32])];

        let prepared = simulate_transaction_with_auth(tx, &env, &smart_account, &signers, 9999)
            .await
            .unwrap();

        // The invoke op now carries a signed Address entry.
        let OperationBody::InvokeHostFunction(op) = &prepared.operations[0].body else {
            panic!("expected invoke-host-function op");
        };
        assert_eq!(op.auth.len(), 1);
        let SorobanCredentials::Address(creds) = &op.auth[0].credentials else {
            panic!("expected Address credentials");
        };
        assert_eq!(creds.signature_expiration_ledger, 9999);
        assert!(!matches!(creds.signature, ScVal::Void));

        // Re-priced from the enforce pass: base fee + resource fee + buffer.
        assert!(matches!(prepared.ext, TransactionExt::V1(_)));
        assert_eq!(
            prepared.fee,
            (DEFAULT_TRANSACTION_FEES as u64 + min_resource_fee + AUTH_FEE_BUFFER) as u32
        );
    }

    #[tokio::test]
    async fn simulate_with_auth_errors_on_unsignable_address() {
        // Simulation asks for a signature from address 8, but we only hold
        // signers for address 7.
        let response = sim_response(&[address_entry(&contract_address(8), 1)], 100);
        let env = mock_env(None, Some(Ok(response)), None);

        let tx = build_invoke_tx(&env).await;
        let signers = [Signer::from(&[0xA1; 32])];

        let err = simulate_transaction_with_auth(tx, &env, &contract_address(7), &signers, 9999)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SorobanHelperError::NotSupported(_)),
            "got {err:?}"
        );
    }
}
