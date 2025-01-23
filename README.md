# Third Party Reporting Implementation
This is the implementation and benchmarking of [Third Party Reporting](https://github.com/SabaEskandarian/ThirdPartyReporting).

## Overview
Each scheme is separated into an individual `lib_{scheme}.rs` file following a common interface as outlined in the above paper. In additition, testing follows a configurable flow that can be used to verify that the scheme works with an arbitrary number of clients, moderators, and message sizes. Benchmarking is done through [Criterion](https://github.com/bheisler/criterion.rs) for each method from each of the schemes and is also parameterized by the same variables as testing. 

## Testing
To run the entire flow of any of the schemes, run the `main.rs` file using `cargo run` with the appropriate parameters.
- test_basic for the basic scheme
- test_mod_priv for the moderator privacy scheme
- test_constant_mod_priv for the moderator privacy scheme with constant size tags

## Benchmarking
All benchmarks are located in the `benches` folder. Benchmarking is done using [Criterion](https://github.com/bheisler/criterion.rs)
- Run `cargo bench` to run all benchmarks

## Basic Scheme
### Primitives
- Aes256Gcm
- HmacSha256
- El Gamal
