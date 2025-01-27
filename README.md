# Third Party Reporting Implementation
This is the implementation and benchmarking of [Third Party Reporting](https://github.com/SabaEskandarian/ThirdPartyReporting).

## Overview
Each scheme is separated into an individual `lib_{scheme}.rs` file following a common interface as outlined in the above paper. In additition, testing follows a configurable flow that can be used to verify that the scheme works with an arbitrary number of clients, moderators, and message sizes. Benchmarking is done through [Criterion](https://github.com/bheisler/criterion.rs) for each method from each of the schemes and is also parameterized by the same variables as testing. 

## Testing
To run the entire flow of any of the schemes, run the `main.rs` file using `cargo run --` with the appropriate parameters 
```
Usage: third_party_reporting [OPTIONS]

Options:
      --basic
      --mod-priv
      --constant-mod-priv
      --num-clients <NUM_CLIENTS>        [default: 10]
      --num-moderators <NUM_MODERATORS>  [default: 10]
      --msg-size <MSG_SIZE>              [default: 10]
  -h, --help                             Print help
  -V, --version                          Print version
```
For example `cargo run -- --basic --mod-priv --num-clients 20 --msg-size 30` runs the basic scheme and moderator privacy scheme with 20 clients and a message size of 30 bytes.

## Benchmarking
All benchmarks are located in the `benches` folder. Benchmarking is done using [Criterion](https://github.com/bheisler/criterion.rs). Criterion usually runs each test for some large number of iterations >10k and reports common statistics. To run all benchmarks, simply use `cargo bench`. Criterion also uses regex on the benchmark names [Command Line Options](https://bheisler.github.io/criterion.rs/book/user_guide/command_line_options.html).
- Run `cargo bench` to run all benchmarks
- Run `cargo bench -- {scheme}` to run only benchmarks on the {scheme}, i.e. basic, mod_priv, constant_mod_priv

## Basic Scheme
### Primitives
- Aes256Gcm
- HmacSha256
- El Gamal
- Compactly Committing Authenticated Encryption [CCAE](https://eprint.iacr.org/2022/1670)

## Moderator Privacy Scheme
- All basic scheme primitives
- El Gamal Proxy Re-Encryption [Improved Proxy Re-Enc](https://eprint.iacr.org/2005/028.pdf) and [Atomic Proxy Crypto](https://www.researchgate.net/publication/2581968_Atomic_Proxy_Cryptography)
