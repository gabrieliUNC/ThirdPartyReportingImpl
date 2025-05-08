use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_mod_priv as mod_priv;
use third_party_reporting::lib_constant_mod_priv as constant_mod_priv;

use third_party_reporting::lib_plain as p;
use std::time::{Instant, Duration};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm};
use rand::distributions::Alphanumeric;
use third_party_reporting::lib_common::CTX_LEN;
use rand::distributions::DistString;
const N: usize = 1000; // Number of trials to average each operation over

use clap::Parser;
use blstrs as blstrs;
use std::env;
use group::prime::PrimeCurveAffine;


#[derive(Parser, Debug)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Args {
    #[arg(long, default_value_t = false)]
    basic: bool,

    #[arg(long, default_value_t = false)]
    mod_priv: bool,

    #[arg(long, default_value_t = false)]
    const_priv: bool,

    #[arg(long, default_value_t = 1)]
    num_clients: usize,

    #[arg(long, default_value_t = 10)]
    num_moderators: usize,

    #[arg(long, default_value_t = 100)]
    msg_size: usize,

    #[arg(long, default_value_t = false)]
    test: bool,

    #[arg(long, default_value_t = false)]
    test_e2ee: bool
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    let args = Args::parse();

    if args.test {
        test();
        return;
    }

    if args.basic {
        test_basic(args.num_clients, args.msg_size, args.num_moderators);
    }
    
    if args.mod_priv {
        test_priv(args.num_clients, args.msg_size, args.num_moderators);
    }
    
    if args.const_priv {
        test_constant_mod_priv(args.num_clients, args.msg_size, args.num_moderators);
    }

    if args.test_e2ee {
        // Print the plain E2EE franking test results. Unlike our schemes, this does not rely
        // on a mix-network configuration with multiple servers, so we don't vary n_servers.
        // There is only one line of output per message size.
        

        let (t_send, t_mod_process, t_read, t_moderate, send_size, rep_size) = test_plain(args.msg_size);
        let res = format!("{: <10}-         {: <10}-              {: <15}{: <15}-              {: <15}{: <15}{: <10}-         {: <10}-",
            "Plain", args.msg_size,
            t_send.div_f32(N as f32).as_nanos(),
            t_mod_process.div_f32(N as f32).as_nanos(),
            t_read.div_f32(N as f32).as_nanos(),
            t_moderate.div_f32(N as f32).as_nanos(),
            send_size, rep_size);
        println!("{}", res);
    }

}

pub fn test() {
    let g2 = blstrs::G2Affine::generator();
    println!("{:?}", g2);
}


// Method for running the constant moderator privacy scheme flow with variable number of clients, msg sizes
// and number of moderators
pub fn test_constant_mod_priv(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Moderator Privacy Scheme ====================");
    println!();

    // Initialize Platform
    let mut platform = constant_mod_priv::test_setup_platform();

    // Initialize Moderators
    let (moderators, pks) = constant_mod_priv::test_setup_mod(&mut platform, num_moderators);

    // Initialize Clients
    let clients = constant_mod_priv::test_init_clients(num_clients);

    // Prepare messages
    let ms = constant_mod_priv::test_init_messages(num_clients, msg_size);

    // Send messages
    let c1c2ad = constant_mod_priv::test_send(num_clients, &moderators, &clients, &ms, true);

    // Process messages
    let sigma_st = constant_mod_priv::test_process(num_clients, msg_size, &c1c2ad, &platform, true);

    // Read messages
    let report_docs = constant_mod_priv::test_read(num_clients, &c1c2ad, &sigma_st, &clients, &pks, true);

    // Generate reports
    let reports = constant_mod_priv::test_report(num_clients, &report_docs, true);

    // Moderate reports
    constant_mod_priv::test_moderate(num_clients, &reports, &moderators, true);


    println!();
    println!("======================== Finished Testing Moderator Privacy Scheme ====================");
    println!();
    println!();

}


// Method for running the moderator privacy scheme flow with variable number of clients, msg sizes
// and number of moderators
pub fn test_priv(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Moderator Privacy Scheme ====================");
    println!();

    // Initialize Platform
    let mut platform = mod_priv::test_setup_platform();

    // Initialize Moderators
    let (moderators, pks) = mod_priv::test_setup_mod(&mut platform, num_moderators);

    // Initialize Clients
    let clients = mod_priv::test_init_clients(num_clients);

    // Prepare messages
    let ms = mod_priv::test_init_messages(num_clients, msg_size);

    // Send messages
    let c1c2ad = mod_priv::test_send(num_clients, &moderators, &clients, &ms, true);

    // Process messages
    let sigma_st = mod_priv::test_process(num_clients, msg_size, &c1c2ad, &platform, true);

    // Read messages
    let rds = mod_priv::test_read(num_clients, &c1c2ad, &sigma_st, &clients, &pks, true);

    // Generate reports
    let reports = mod_priv::test_report(num_clients, &rds, true);

    // Moderate reports
    mod_priv::test_moderate(num_clients, &reports, &moderators, true);


    println!();
    println!("======================== Finished Testing Moderator Privacy Scheme ====================");
    println!();
    println!();
}

// Method for running the whole basic scheme flow with variable number of clients / msgs sent, msg_size, and 
// number of moderators
pub fn test_basic(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Basic Scheme ====================");
    println!();

    // Initialize platform
    let mut platform = basic::test_basic_setup_platform();

    // Initialize Moderators
    let (moderators, pks) = basic::test_basic_setup_mod(&mut platform, num_moderators);

    // Initialize Clients
    let clients = basic::test_basic_init_clients(num_clients);

    // Prepare messages
    let ms = basic::test_basic_init_messages(num_clients, msg_size);

    // Send messages
    let c1c2ad = basic::test_basic_send(num_clients, num_moderators, &clients, &ms, true);

    // Process messages
    let sigma_st = basic::test_basic_process(num_clients, msg_size, &c1c2ad, &platform, true);

    // Read messages and generate report docs
    let rds = basic::test_basic_read(num_clients, &c1c2ad, &sigma_st, &clients, &pks, true);

    // Generate reports
    let reports = basic::test_report(num_clients, &rds, true);

    // Moderate reports
    basic::test_basic_moderate(num_clients, &reports, &moderators, true);



    println!();
    println!("======================== Completed Testing Basic Scheme ====================");
    println!();
    println!();
}

pub fn test_plain(msg_size: usize) -> (Duration, Duration, Duration, Duration, usize, usize) {

    // Initialize senders and receivers
    let mut senders: Vec<p::Client> = Vec::with_capacity(N);
    for _i in 0..N {
        let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
        let sender = p::Client::new(k_r);
        senders.push(sender);
    }

	let moderator = p::Moderator::new();

	// Send a message
    let mut ms: Vec<String> = Vec::with_capacity(N);
    for _i in 0..N {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }

	// Sender
    let mut c1c2s: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(N);
    let mut t_send = Duration::ZERO;
    for i in 0..N {

        // Time the message sending step. Note that there's no pre-processing in the
        // basic E2EE franking scheme.
        let now = Instant::now();
        let (c1, c2) = p::Client::send(&ms[i], senders[i].k_r);
        t_send += now.elapsed();

        // Not bundling offline and online
        // let (c1, c2, c3) = p::Client::send(&ms[i], senders[i].k_r, &pks, n);
        c1c2s.push((c1, c2));
    }

	// Moderator
    let mut ctxs: Vec<String> = Vec::with_capacity(N);
    let mut sigmas: Vec<Vec<u8>> = Vec::with_capacity(N);
	let mut t_mod_process = Duration::ZERO;
	for i in 0..N {
        let (_, c2) = c1c2s[i].clone();

        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
        ctxs.push(ctx.clone());

        // Time the moderator processing step. No other servers are present in the plain
        // E2EE franking scheme.
		let now = Instant::now();
        let sigma = p::Moderator::mod_process(&moderator.k_m, &c2, &ctx);
		t_mod_process += now.elapsed();
        sigmas.push(sigma.clone());

    }

	let send_size = ctxs[0].len() + sigmas[0].len() + c1c2s[0].1.len();

	// Receiver
    let mut reports: Vec<(String, String, (Vec<u8>, Vec<u8>), Vec<u8>)> = Vec::with_capacity(N);
	let mut t_read = Duration::ZERO;
	for i in 0..N {
        let k_r = senders[i].k_r;
        let (c1, c2) = c1c2s[i].clone();
		let ctx = ctxs[i].clone();
		let sigma = sigmas[i].clone();
		let st = (c2, ctx, sigma);
        // Time the message reading.
		let now = Instant::now();
	    let (m, ctx, rd, sigma) = p::Client::read(k_r, c1, st);
		t_read += now.elapsed();
        reports.push((m, ctx, rd, sigma));
    }

    let rep_size = reports[0].2.0.len() + reports[0].2.1.len() + reports[0].3.len();

	// Reporting back to moderator
	let mut t_moderate = Duration::ZERO;
	for i in 0..N {
        let (m, ctx, rd, sigma) = reports[i].clone();
        // Time the report moderation.
		let now = Instant::now();
        let res = p::Moderator::moderate(&moderator.k_m, &m, &ctx, rd, sigma);
		t_moderate += now.elapsed();
        if !res {
            panic!("Report failed");
        } else {
		}
    }

    (t_send, t_mod_process, t_read, t_moderate, send_size, rep_size)
}
