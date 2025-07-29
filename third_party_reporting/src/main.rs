use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_mod_priv as mod_priv;
use third_party_reporting::lib_constant_mod_priv as constant_mod_priv;
use third_party_reporting::lib_plain as plain;

use clap::Parser;


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

    #[arg(long, default_value_t = 1)]
    num_moderators: usize,

    #[arg(long, default_value_t = 100)]
    msg_size: usize,

    #[arg(long, default_value_t = false)]
    test_e2ee: bool
}

fn main() {

    let args = Args::parse();

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
        test_e2ee(args.num_clients, args.msg_size);
    }

}

// Run the plain franking scheme
pub fn test_e2ee(num_clients: usize, msg_size: usize) {
    println!();
    println!("======================== Started Testing Plain Franking Scheme ====================");
    println!();
    

    // Initialize Moderator
    let moderator = plain::Moderator::new();

    // Initialize Clients
    let clients = plain::test_init_clients(num_clients);

    // Prepare messages
    let mut ms: Vec<Vec<String>> = Vec::new();
    for _i in 0..num_clients {
        ms.push(plain::test_init_messages(1, msg_size));
    }

    // Send messages
    let c1c2s = plain::test_send(&clients, &ms, true);

    // Process messages
    let sigmas = plain::test_process(&moderator, &c1c2s);

    // Read messages
    let reports = plain::test_read(&clients, &c1c2s, &sigmas, true);

    // Moderate reports
    plain::test_moderate(&moderator, &reports, &ms, true);


    println!();
    println!("======================== Finished Testing Plain Franking Scheme with ====================");
    println!();

}


// Method for running the constant moderator privacy scheme flow with variable number of clients, msg sizes
// and number of moderators
pub fn test_constant_mod_priv(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Constant Moderator Privacy Scheme with {} moderators ====================", num_moderators);
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
    println!("======================== Finished Testing Constant Moderator Privacy Scheme with {} moderators ====================", num_moderators);
    println!();
    println!();

}


// Method for running the moderator privacy scheme flow with variable number of clients, msg sizes
// and number of moderators
pub fn test_priv(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Moderator Privacy Scheme with {} moderators ====================", num_moderators);
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
    println!("======================== Finished Testing Moderator Privacy Scheme with {} moderators ====================", num_moderators);
    println!();
    println!();
}

// Method for running the whole basic scheme flow with variable number of clients / msgs sent, msg_size, and 
// number of moderators
pub fn test_basic(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Basic Scheme with {} moderators ====================", num_moderators);
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
    println!("======================== Completed Testing Basic Scheme with {} moderators ====================", num_moderators);
    println!();
    println!();
}
