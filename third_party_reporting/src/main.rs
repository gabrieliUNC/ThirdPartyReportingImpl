use third_party_reporting::lib_basic as basic;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use openssl::rsa::Rsa;
use openssl::pkey::Public;
use rand::Rng;
use rand::thread_rng;

fn main() {

    test_basic(1000, 1000, 190);
}

// Basic scheme testing decomposition for benchmarking
// still have num_moderators as a variable despite 
// this having minimal effect on running time
// as clients choose 1 moderator and server
// encrypts under 1 moderator's pk

// SetupPlatform(1^lambda)
pub fn test_basic_setup_platform() -> basic::Platform {
    let platform = basic::Platform::new();

    platform
}

// SetupMod(pk_reg, 1^lambda)
pub fn test_basic_setup_mod(mut platform: basic::Platform, num_moderators: usize) -> (basic::Platform, Vec<basic::Moderator>, Vec<Rsa<Public>>) {
    let mut moderators: Vec<basic::Moderator> = Vec::with_capacity(num_moderators);
    let mut pks: Vec<Rsa<Public>> = Vec::with_capacity(num_moderators);

    for _i in 0..num_moderators {
        let moderator = basic::Moderator::new(platform.k_reg.clone());
        platform.sk_p.push((moderator.sk_p.clone(), moderator.pk_mod.clone()));
        pks.push(moderator.pk_mod.clone());
        moderators.push(moderator);
    }


    (platform, moderators, pks)
}

// Setup Clients
pub fn test_basic_init_clients(num_clients: usize, msg_size: usize) -> (Vec<basic::Client>, Vec<String>) {
    let mut clients: Vec<basic::Client> = Vec::with_capacity(num_clients);
    for _i in 0..num_clients {
        let client = basic::Client::new();
        clients.push(client);
    }

    // Prepare messages
    let mut ms: Vec<String> = Vec::with_capacity(num_clients);
    for _i in 0..num_clients {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }

    (clients, ms)
}

// send(k, m, pk_i)
pub fn test_basic_send(num_clients: usize, clients: &Vec<basic::Client>, ms: Vec<String>) -> Vec<(Vec<u8>, Vec<u8>, u32)> {
    let mut c1c2ad: Vec<(Vec<u8>, Vec<u8>, u32)> = Vec::with_capacity(num_clients);
    // send message i to client i to be moderated by random mod
    let mut rng = thread_rng();
    for i in 0..num_clients {
        let mod_i = rng.gen_range(0..10);
        let (c1, c2, ad) = basic::Client::send(clients[i].msg_key, &ms[i].clone(), mod_i);
        
        c1c2ad.push((c1, c2, ad));
    }

    c1c2ad
}

// process(k_p, ks, c1, c2, ad, ctx)
pub fn test_basic_process(num_clients: usize, msg_size: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>, platform: &basic::Platform) -> Vec<(Vec<u8>, (Vec<u8>, u32))> {
    let mut sigma_st: Vec<(Vec<u8>, (Vec<u8>, u32))> = Vec::with_capacity(num_clients);
    // Platform processes message
    for i in 0..num_clients {
        let (c1, c2, ad) = &c1c2ad[i];
        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        println!("Adding context: {}", ctx);
        let (sigma, st) = basic::Platform::process(platform.k_p.clone(), &platform.sk_p, &c1, &c2, *ad, &(ctx.as_bytes().to_vec()));

        sigma_st.push((sigma, st));
    }

    sigma_st
}

// read(k, pks, c1, c2, sigma, st)
pub fn test_basic_read(num_clients: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>, sigma_st: &Vec<(Vec<u8>, (Vec<u8>, u32))>, clients: &Vec<basic::Client>, pks: &Vec<Rsa<Public>>) -> Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>))> {
    // Receive messages
    let mut reports: Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>))> = Vec::with_capacity(num_clients);
    // Receive message 0 from client 0 to be moderated by randomly selected moderator mod_i
    for i in 0..num_clients {
        let (c1, c2, _ad) = &c1c2ad[i];
        let (sigma, st) = &sigma_st[i];
        let (message, ad, report) = basic::Client::read(clients[i].msg_key, &pks, &c1, &c2, &sigma, &st);

        println!("Received message: {}", message);
        reports.push((message, ad, report));
    }

    reports
}

// moderate(sk_mod, sk_p, m, report)
pub fn test_basic_moderate(num_clients: usize, reports: &Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>))>, moderators: &Vec<basic::Moderator>) {
    // Moderate messages
    for i in 0..num_clients {
        let (message, ad, report) = &reports[i];
        let ad = usize::try_from(*ad).unwrap();
        let ctx = basic::Moderator::moderate(moderators[ad].sk_mod.clone(), moderators[ad].sk_p.clone(), &message, report.clone());
        println!("Moderated message successfully with context: {:?}", ctx);
    }

}

// Method for running the whole basic scheme flow with variable number of clients / msgs sent, msg_size, and 
// number of moderators
pub fn test_basic(num_clients: usize, msg_size: usize, num_moderators: usize) {
    // Initialize platform
    let platform = test_basic_setup_platform();

    // Initialize Moderators
    let (platform, moderators, pks) = test_basic_setup_mod(platform, num_moderators);

    // Initialize Clients
    let (clients, ms) = test_basic_init_clients(num_clients, msg_size);

    // Send messages
    let c1c2ad = test_basic_send(num_clients, &clients, ms);

    // Process messages
    let sigma_st = test_basic_process(num_clients, msg_size, &c1c2ad, &platform);

    // Read messages and generate reports
    let reports = test_basic_read(num_clients, &c1c2ad, &sigma_st, &clients, &pks);

    // Moderate reports
    test_basic_moderate(num_clients, &reports, &moderators);
}
