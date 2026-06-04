#![no_std]
//! # Minimal multisig smart account (test fixture)
//!
//! A deliberately small **contract account** (a `C…` address with a custom
//! `__check_auth`) used by the deployer integration tests to exercise the
//! "`project_root` owner is a contract account" path — see
//! `packages/deployer/tests/multisig_contract.rs` and `SOROBAN_RS.md`.
//!
//! It is **not** part of the WarpDrive pipeline; it is a stand-in for a real
//! smart wallet. The design mirrors the shape of OpenZeppelin's
//! `stellar-accounts` smart account (signers + a threshold, signatures checked
//! in `__check_auth`) but is reduced to a single self-contained contract — no
//! verifier/policy sub-contracts — and pinned to this repo's `soroban-sdk` so
//! it builds alongside the other contracts.
//!
//! Authorization model: an `n`-of-`m` ed25519 multisig. The constructor records
//! a set of ed25519 public keys and a threshold; `__check_auth` accepts a list
//! of `(public_key, signature)` pairs and authorizes when at least `threshold`
//! distinct registered keys produce a valid signature over the host's
//! `signature_payload`.

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Bytes, BytesN, Env, Vec,
};

#[contract]
pub struct MultisigAccount;

/// One signer's contribution: the ed25519 public key and its 64-byte signature
/// over the host-provided `signature_payload`.
#[contracttype]
#[derive(Clone)]
pub struct Ed25519Signature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The constructor never ran (no signer set / threshold stored).
    NotInitialized = 1,
    /// A supplied signature is from a key that is not a registered signer.
    UnknownSigner = 2,
    /// The same signer was supplied more than once.
    DuplicateSigner = 3,
    /// Fewer than `threshold` distinct valid signatures were supplied.
    InsufficientSignatures = 4,
}

#[contracttype]
enum DataKey {
    /// `Vec<BytesN<32>>` — the registered ed25519 public keys.
    Signers,
    /// `u32` — how many distinct valid signatures authorize a call.
    Threshold,
}

#[contractimpl]
impl MultisigAccount {
    /// Register the signer set and the approval threshold (e.g. `threshold = 2`
    /// with two signers is a 2-of-2).
    pub fn __constructor(env: Env, signers: Vec<BytesN<32>>, threshold: u32) {
        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
    }

    /// The registered signer public keys.
    pub fn signers(env: Env) -> Vec<BytesN<32>> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// The approval threshold.
    pub fn threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(0)
    }
}

#[contractimpl]
impl CustomAccountInterface for MultisigAccount {
    type Signature = Vec<Ed25519Signature>;
    type Error = Error;

    /// Authorize iff at least `threshold` distinct registered signers each
    /// produced a valid ed25519 signature over `signature_payload`. A bad
    /// signature traps inside `ed25519_verify`, which fails the whole call.
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Vec<Ed25519Signature>,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let signers: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        let message = Bytes::from_array(&env, &signature_payload.to_array());
        let mut seen: Vec<BytesN<32>> = Vec::new(&env);
        for sig in signatures.iter() {
            if !signers.contains(&sig.public_key) {
                return Err(Error::UnknownSigner);
            }
            if seen.contains(&sig.public_key) {
                return Err(Error::DuplicateSigner);
            }
            env.crypto()
                .ed25519_verify(&sig.public_key, &message, &sig.signature);
            seen.push_back(sig.public_key);
        }

        if seen.len() < threshold {
            return Err(Error::InsufficientSignatures);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;
