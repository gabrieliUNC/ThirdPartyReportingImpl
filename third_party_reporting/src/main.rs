use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_mod_priv as mod_priv;


fn main() {
    test_priv(10, 10, 10);
    // basic::test_proxy();
    //test_basic(10, 10, 10);
}


// Method for running the moderator privacy scheme flow with variable number of clients, msg sizes
// and number of moderators
pub fn test_priv(num_clients: usize, msg_size: usize, num_moderators: usize) {
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
    let reports = mod_priv::test_read(num_clients, &c1c2ad, &sigma_st, &clients, &pks, true);

    // Moderate reports
    mod_priv::test_moderate(num_clients, &reports, &moderators, true);
}

// Method for running the whole basic scheme flow with variable number of clients / msgs sent, msg_size, and 
// number of moderators
pub fn test_basic(num_clients: usize, msg_size: usize, num_moderators: usize) {
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
}
