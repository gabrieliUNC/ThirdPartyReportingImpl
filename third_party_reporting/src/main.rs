use third_party_reporting::lib_basic as basic;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use openssl::rsa::Rsa;
use openssl::pkey::Public;

fn main() {


    test_basic(10, 10);
}

pub fn test_basic(n: usize, msg_size: usize) {
    // Initialize platform
    let mut platform = basic::Platform::new();

    // Initialize Moderators
    let mut moderators: Vec<basic::Moderator> = Vec::with_capacity(n);
    let mut pks: Vec<Rsa<Public>> = Vec::with_capacity(n);

    for _i in 0..n {
        let moderator = basic::Moderator::new(platform.k_reg.clone());
        platform.sk_p.push((moderator.sk_p.clone(), moderator.pk_mod.clone()));
        pks.push(moderator.pk_mod.clone());
        moderators.push(moderator);
    }


    // Initialize Clients
    let mut clients: Vec<basic::Client> = Vec::with_capacity(n);
    for _i in 0..n {
        let client = basic::Client::new();
        clients.push(client);
    }

    // Prepare messages
    let mut ms: Vec<String> = Vec::with_capacity(n);
    for _i in 0..n {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }


    // Send messages
    let c1c2ad: Vec<(Vec<u8>, Vec<u8>, u32)> = Vec::with_capacity(n);

    // Send message 0 from client 0 to be moderated by moderator 0
    println!("Sending message: {}", ms[0]);
    let (c1, c2, ad) = basic::Client::send(clients[0].msg_key, &ms[0].clone(), 0);


    // Platform processes message
    let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
    println!("Adding context: {}", ctx);
    let (sigma, st) = basic::Platform::process(platform.k_p.clone(), &platform.sk_p, &c1, &c2, ad, &(ctx.as_bytes().to_vec()));


    // Receive messages
    
    // Receive message 0 from client 0 to be moderated by moderator 0
    let (message, ad, report) = basic::Client::read(clients[0].msg_key, &pks, &c1, &c2, &sigma, &st);
    println!("Received message: {}", message);



    // Moderate messages
    let ctx = basic::Moderator::moderate(moderators[0].sk_mod.clone(), moderators[0].sk_p.clone(), &message, report);
    println!("Moderated message successfully with context: {:?}", ctx);
}
