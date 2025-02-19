use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_mod_priv as mod_priv;
use third_party_reporting::lib_constant_mod_priv as constant_mod_priv;
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

    #[arg(long, default_value_t = 10)]
    num_clients: usize,

    #[arg(long, default_value_t = 10)]
    num_moderators: usize,

    #[arg(long, default_value_t = 10)]
    msg_size: usize,

    #[arg(long, default_value_t = false)]
    test: bool
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


    println!("======================== Finished Testing Moderator Privacy Scheme ====================");
    println!();
    println!();

}


// Method for running the moderator privacy scheme flow with variable number of clients, msg sizes
// and number of moderators
pub fn test_priv(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Moderator Privacy Scheme ====================");
    println!();
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


    println!("======================== Finished Testing Moderator Privacy Scheme ====================");
    println!();
    println!();
}

// Method for running the whole basic scheme flow with variable number of clients / msgs sent, msg_size, and 
// number of moderators
pub fn test_basic(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Basic Scheme ====================");
    println!();
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

    // Read messages and generate reports
    let reports = basic::test_basic_read(num_clients, &c1c2ad, &sigma_st, &clients, &pks, true);

    // Moderate reports
    basic::test_basic_moderate(num_clients, &reports, &moderators, true);


    println!("======================== Completed Testing Basic Scheme ====================");
    println!();
    println!();
}
