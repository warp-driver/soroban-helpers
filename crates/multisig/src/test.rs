//! Unit tests for the minimal 2-of-2 multisig smart account.
//!
//! Two things are proven here, and together they are the "valid setup" the
//! deployer integration test (`packages/deployer/tests/multisig_contract.rs`)
//! mirrors against a live network:
//!
//!   1. **`__check_auth` enforces the quorum** over *real* ed25519 signatures
//!      (`try_invoke_contract_check_auth` — the host-side entry point Soroban
//!      uses during a `require_auth` call).
//!   2. **The account custodies and moves tokens under its own authority** — it
//!      is minted a balance and then transfers half of it out, where the
//!      transfer is authorized by a real, signed `SorobanAuthorizationEntry`
//!      that the host verifies through `__check_auth`. No `mock_all_auths`: the
//!      only mocked authorization is the *asset issuer's* `mint`.
//!
//! Test (2) is the **signing recipe** the deployer's `call_with_multisig`
//! replays against testnet: build the `HashIdPreimage::SorobanAuthorization`,
//! SHA-256 it, sign that digest with each ed25519 key, and hand the host a
//! `Vec<Ed25519Signature>` as the credential's signature.

extern crate std;

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::{
    auth::{Context, ContractContext},
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    token, vec,
    xdr::{
        Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Int128Parts, InvokeContractArgs,
        Limits, ScAddress, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec,
        SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, VecM, WriteXdr,
    },
    Address, BytesN, Env, IntoVal, Symbol, Val, Vec,
};

use crate::{Ed25519Signature, Error, MultisigAccount};

/// The network id the test host signs/verifies auth payloads against (the
/// testutils default; pinned so the off-chain digest is deterministic).
const NETWORK_ID: [u8; 32] = [0u8; 32];

/// A deterministic ed25519 keypair from a seed byte.
fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey(env: &Env, sk: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &sk.verifying_key().to_bytes())
}

/// Sign `payload` with `sk`, packaged as the contract's `Ed25519Signature`.
fn sign(env: &Env, sk: &SigningKey, payload: &BytesN<32>) -> Ed25519Signature {
    Ed25519Signature {
        public_key: pubkey(env, sk),
        signature: BytesN::from_array(env, &sk.sign(&payload.to_array()).to_bytes()),
    }
}

/// Register the account with the given signers and threshold (runs the ctor).
fn register(env: &Env, signers: &[&SigningKey], threshold: u32) -> Address {
    let mut keys = Vec::new(env);
    for sk in signers {
        keys.push_back(pubkey(env, sk));
    }
    env.register(MultisigAccount, (keys, threshold))
}

/// A `Vec<Context>` describing a token `transfer` — what the account is asked
/// to authorize. `__check_auth` ignores the contexts, but a realistic one keeps
/// the test honest about *what* is being approved.
fn transfer_context(env: &Env) -> Vec<Context> {
    vec![
        env,
        Context::Contract(ContractContext {
            contract: Address::generate(env),
            fn_name: Symbol::new(env, "transfer"),
            args: ().into_val(env),
        }),
    ]
}

/// Drive `__check_auth` exactly as the Soroban host would during `require_auth`.
fn check_auth(
    env: &Env,
    account: &Address,
    payload: &BytesN<32>,
    sigs: Vec<Ed25519Signature>,
) -> Result<(), Error> {
    let signature: Val = sigs.into_val(env);
    env.try_invoke_contract_check_auth::<Error>(account, payload, signature, &transfer_context(env))
        .map_err(|e| e.expect("host (non-contract) error in __check_auth"))
}

#[test]
fn quorum_of_two_authorizes() {
    let env = Env::default();
    let (a, b) = (keypair(0xA1), keypair(0xB2));
    let account = register(&env, &[&a, &b], 2);

    let payload = BytesN::from_array(&env, &[7u8; 32]);
    let sigs = vec![&env, sign(&env, &a, &payload), sign(&env, &b, &payload)];

    check_auth(&env, &account, &payload, sigs).expect("a valid 2-of-2 must authorize");
}

#[test]
fn single_signature_is_below_threshold() {
    let env = Env::default();
    let (a, b) = (keypair(0xA1), keypair(0xB2));
    let account = register(&env, &[&a, &b], 2);

    let payload = BytesN::from_array(&env, &[7u8; 32]);
    let sigs = vec![&env, sign(&env, &a, &payload)];

    assert_eq!(
        check_auth(&env, &account, &payload, sigs),
        Err(Error::InsufficientSignatures),
    );
}

#[test]
fn unknown_signer_is_rejected() {
    let env = Env::default();
    let (a, b) = (keypair(0xA1), keypair(0xB2));
    let account = register(&env, &[&a, &b], 2);

    let intruder = keypair(0xCC);
    let payload = BytesN::from_array(&env, &[7u8; 32]);
    // A perfectly valid signature — but from a key the account doesn't know.
    let sigs = vec![
        &env,
        sign(&env, &a, &payload),
        sign(&env, &intruder, &payload),
    ];

    assert_eq!(
        check_auth(&env, &account, &payload, sigs),
        Err(Error::UnknownSigner),
    );
}

#[test]
fn duplicate_signer_does_not_satisfy_quorum() {
    let env = Env::default();
    let (a, b) = (keypair(0xA1), keypair(0xB2));
    let account = register(&env, &[&a, &b], 2);

    let payload = BytesN::from_array(&env, &[7u8; 32]);
    // The same signer twice must not count as two distinct approvals.
    let sigs = vec![&env, sign(&env, &a, &payload), sign(&env, &a, &payload)];

    assert_eq!(
        check_auth(&env, &account, &payload, sigs),
        Err(Error::DuplicateSigner),
    );
}

// ── Real-authorization transfer ──────────────────────────────────────────────
//
// The helpers below build a signed `SorobanAuthorizationEntry` by hand — the
// exact bytes the Soroban host expects — so the transfer is authorized by the
// account's *own* 2-of-2 quorum rather than `mock_all_auths`. The deployer test
// replays this same recipe via wasi-soroban-rs.

fn sym(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(s.try_into().expect("symbol")))
}

fn bytes_scval(b: &[u8]) -> ScVal {
    ScVal::Bytes(ScBytes(b.to_vec().try_into().expect("bytes")))
}

fn i128_scval(v: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (v >> 64) as i64,
        lo: v as u64,
    })
}

fn scaddr(addr: &Address) -> ScAddress {
    match ScVal::from(addr) {
        ScVal::Address(a) => a,
        other => panic!("not an address: {other:?}"),
    }
}

/// One signer's `Ed25519Signature` as the host-encoded `ScVal` (a struct map
/// with keys sorted: `public_key` before `signature`).
fn ed25519_sig_scval(sk: &SigningKey, payload: &[u8; 32]) -> ScVal {
    let entries = std::vec![
        ScMapEntry {
            key: sym("public_key"),
            val: bytes_scval(&sk.verifying_key().to_bytes()),
        },
        ScMapEntry {
            key: sym("signature"),
            val: bytes_scval(&sk.sign(payload).to_bytes()),
        },
    ];
    ScVal::Map(Some(ScMap(entries.try_into().expect("sig map"))))
}

#[test]
fn account_moves_funds_under_its_own_quorum() {
    let env = Env::default();
    env.ledger().set_network_id(NETWORK_ID);

    let (a, b) = (keypair(0xA1), keypair(0xB2));
    let account = register(&env, &[&a, &b], 2);

    // Mint a balance, authorized ONLY by the asset issuer (not the account).
    let issuer = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(issuer.clone());
    let admin = token::StellarAssetClient::new(&env, &sac.address());
    let coin = token::TokenClient::new(&env, &sac.address());
    env.mock_auths(&[MockAuth {
        address: &issuer,
        invoke: &MockAuthInvoke {
            contract: &sac.address(),
            fn_name: "mint",
            args: (account.clone(), 100i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    admin.mint(&account, &100);
    assert_eq!(coin.balance(&account), 100);

    // Move half — authorized by the account's real 2-of-2 quorum.
    let recipient = Address::generate(&env);
    let amount = 50i128;
    let nonce = 0xC0FFEE_i64;
    let expiration = 10_000_u32;

    // The invocation the host requires `account` to authorize: the transfer.
    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: scaddr(&sac.address()),
            function_name: "transfer".try_into().expect("fn name"),
            args: std::vec![
                ScVal::from(&account),
                ScVal::from(&recipient),
                i128_scval(amount)
            ]
            .try_into()
            .expect("args"),
        }),
        sub_invocations: VecM::default(),
    };

    // The digest the host recomputes and feeds to `__check_auth`.
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(NETWORK_ID),
        nonce,
        signature_expiration_ledger: expiration,
        invocation: invocation.clone(),
    });
    let digest: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).expect("xdr")).into();

    // Both signers sign that digest → the credential's signature.
    let signature = ScVal::Vec(Some(ScVec(
        std::vec![
            ed25519_sig_scval(&a, &digest),
            ed25519_sig_scval(&b, &digest)
        ]
        .try_into()
        .expect("sig vec"),
    )));

    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: scaddr(&account),
            nonce,
            signature_expiration_ledger: expiration,
            signature,
        }),
        root_invocation: invocation,
    };

    env.set_auths(&[entry]);
    coin.transfer(&account, &recipient, &amount);

    assert_eq!(coin.balance(&account), 50);
    assert_eq!(coin.balance(&recipient), 50);
}

// ── Same recipe, but signed by wasi-soroban-rs ───────────────────────────────
//
// Proves the library's `sign_auth_entry` produces a credential the host's
// `__check_auth` accepts: we hand it the *unsigned* `Address` entry exactly as
// `simulateTransaction` returns it, then submit what it gives back. This is the
// in-host equivalent of what `simulate_transaction_with_auth` does against a
// live network.

#[test]
fn library_helper_authorizes_transfer() {
    let env = Env::default();
    env.ledger().set_network_id(NETWORK_ID);

    let (a, b) = (keypair(0xA1), keypair(0xB2));
    let account = register(&env, &[&a, &b], 2);

    // Mint a balance, authorized ONLY by the asset issuer (not the account).
    let issuer = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(issuer.clone());
    let admin = token::StellarAssetClient::new(&env, &sac.address());
    let coin = token::TokenClient::new(&env, &sac.address());
    env.mock_auths(&[MockAuth {
        address: &issuer,
        invoke: &MockAuthInvoke {
            contract: &sac.address(),
            fn_name: "mint",
            args: (account.clone(), 100i128).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    admin.mint(&account, &100);
    assert_eq!(coin.balance(&account), 100);

    let recipient = Address::generate(&env);
    let amount = 50i128;
    let nonce = 0xC0FFEE_i64;
    let expiration = 10_000_u32;

    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: scaddr(&sac.address()),
            function_name: "transfer".try_into().expect("fn name"),
            args: std::vec![
                ScVal::from(&account),
                ScVal::from(&recipient),
                i128_scval(amount)
            ]
            .try_into()
            .expect("args"),
        }),
        sub_invocations: VecM::default(),
    };

    // The unsigned credential, exactly as `simulateTransaction` returns it
    // (void signature, expiration not yet set).
    let unsigned = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: scaddr(&account),
            nonce,
            signature_expiration_ledger: 0,
            signature: ScVal::Void,
        }),
        root_invocation: invocation,
    };

    // Sign it with the library helper under test.
    let signers = [
        wasi_soroban_rs::Signer::new(a.clone()),
        wasi_soroban_rs::Signer::new(b.clone()),
    ];
    let signed = wasi_soroban_rs::sign_auth_entry(
        &unsigned,
        &scaddr(&account),
        &signers,
        expiration,
        &Hash(NETWORK_ID),
    )
    .expect("sign_auth_entry");

    env.set_auths(&[signed]);
    coin.transfer(&account, &recipient, &amount);

    assert_eq!(coin.balance(&account), 50);
    assert_eq!(coin.balance(&recipient), 50);
}
