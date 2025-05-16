# Third Party Reporting Implementation
This is the implementation and benchmarking of Third Party Reporting.

## Produce Results
To produce the results shown in the paper, simply give the scripts the correct permissions and execute `run.sh`. This will produce the running time and communication cost numbers for each scheme. Each individual benchmark will be called with moderators ranging from 1 to 1000 (which may take a while to run). Following these benchmarks, the running time table and the plots from the evaluation section of the paper will be produced using the 2 python scripts.
> [!NOTE]  
> The scripts use python3, pandas, and matplotlib. Make sure these are installed to ensure the results are visualized properly.

1. `chmod u+x run.sh`
2. `chmod u+x script.py`
3. `chmod u+x plots.py`
4. `./run.sh`

> [!IMPORTANT]
> Once `run.sh` is called once, you do not need to call it again, unless you want new data from criterion. You can simply call the scripts individually to reproduce the running time table `python3 script.py` and evaluation plots `python3 plots.py`.

## Overview
Each scheme is separated into an individual `lib_{scheme}.rs` file following a common interface as outlined in the above paper. In additition, testing follows a configurable flow that can be used to verify that the scheme works with an arbitrary number of clients, moderators, and message sizes. Benchmarking is done through [Criterion](https://github.com/bheisler/criterion.rs) for each method from each of the schemes and is also parameterized by the same variables as testing. 

## Testing and Communication Cost
To run the entire flow of any of the schemes, run the `main.rs` file using `cargo run --` with the appropriate parameters. This will also print the communication cost for each scheme while the methods are run.
```
Usage: third_party_reporting [OPTIONS]

Options:
      --basic
      --mod-priv
      --const-priv
      --num-clients <NUM_CLIENTS>        [default: 1]
      --num-moderators <NUM_MODERATORS>  [default: 10]
      --msg-size <MSG_SIZE>              [default: 100]
      --test-e2ee
  -h, --help                             Print help
  -V, --version                          Print version
```
For example `cargo run -- --basic --mod-priv --num-clients 20 --msg-size 1024` runs the basic scheme and moderator privacy scheme with 20 clients and a message size of 1kb.

## Running Time
All benchmarks are located in the `benches` folder. Benchmarking is done using [Criterion](https://github.com/bheisler/criterion.rs). Criterion usually runs each test for some large number of iterations (>10k) and reports common statistics. To run all benchmarks, simply use `cargo bench`. Criterion also uses regex on the benchmark names through [Command Line Options](https://bheisler.github.io/criterion.rs/book/user_guide/command_line_options.html).
- Run `cargo bench` to run all benchmarks
- Run `cargo bench -- {scheme}` to run only benchmarks on the {scheme}, i.e. `basic, mod-priv, const-mod-priv`
- Run `cargo bench -- {method}` to compare benchmarks on a specific {method}, i.e. `send, process, moderate`
- Isolate individual tests with `cargo bench -- {scheme}.{method}` i.e. `cargo bench -- mod-priv.send`

## Basic Scheme
### Primitives
- Aes256Gcm
- HmacSha256
- El Gamal
- Compactly Committing Authenticated Encryption [CCAE](https://eprint.iacr.org/2022/1670)

## Moderator Privacy Scheme
- All basic scheme primitives
- El Gamal Proxy Re-Encryption [Improved Proxy Re-Enc](https://eprint.iacr.org/2005/028.pdf) and [Atomic Proxy Crypto](https://www.researchgate.net/publication/2581968_Atomic_Proxy_Cryptography)

## Constant Moderator Privacy Scheme
- All Basic and Moderator Privacy scheme primitives
- BLS Elliptic Curve operations and pairings through the [Blst](https://github.com/supranational/blst/tree/165ec77634495175aefd045a48d3469af6950ea4) library and its rust friendly implementation: [Blstrs](https://github.com/filecoin-project/blstrs)
