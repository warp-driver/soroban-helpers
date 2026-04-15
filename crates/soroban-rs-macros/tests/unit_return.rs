//! Regression test: the `soroban!` macro must emit a `Result<SorobanTransactionResponse,
//! SorobanHelperError>` return type for every generated client method, even when the source
//! contract method returns unit (`()`).
//!
//! The generated body is always `self.contract.invoke(...).await`, which yields
//! `Result<SorobanTransactionResponse, SorobanHelperError>`. If the macro emits an empty
//! return type for unit-returning source methods, the compiler rejects the expansion with
//! E0308: `expected (), found Result<...>`.

use soroban_rs_macros::soroban;

soroban!(
    r#"
    pub struct UnitReturn;

    impl UnitReturn {
        pub fn no_return(env: &Env) {
            // Source returns (). Generated client method must still return
            // Result<SorobanTransactionResponse, SorobanHelperError>.
        }

        pub fn no_return_with_args(env: &Env, a: u32, b: u32) {
            // Same, with arguments.
        }

        pub fn with_return(env: &Env) -> u32 {
            // Control case: already works today.
            0
        }
    }
"#
);

#[test]
fn generated_unit_return_method_returns_result() {
    // Compile-only assertion: if the macro regresses, this file fails to build with E0308.
    // We additionally pin the generated signature by taking a function pointer whose type
    // mentions the expected `Result<_, _>` return.
    fn _assert_signatures(client: &mut UnitReturnClient) {
        let _: &mut dyn FnMut(
            &mut UnitReturnClient,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                    Output = Result<
                        soroban_rs::SorobanTransactionResponse,
                        soroban_rs::SorobanHelperError,
                    >,
                >,
            >,
        > = &mut |c| Box::pin(c.no_return());

        let _: &mut dyn FnMut(
            &mut UnitReturnClient,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                    Output = Result<
                        soroban_rs::SorobanTransactionResponse,
                        soroban_rs::SorobanHelperError,
                    >,
                >,
            >,
        > = &mut |c| {
            let a = soroban_rs::xdr::ScVal::U32(1);
            let b = soroban_rs::xdr::ScVal::U32(2);
            Box::pin(c.no_return_with_args(a, b))
        };

        let _ = client;
    }
}
