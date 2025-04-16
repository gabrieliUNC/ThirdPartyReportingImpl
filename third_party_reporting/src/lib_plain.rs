use rand::RngCore;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand::distributions::Alphanumeric; 
use rand::distributions::DistString;
use bincode;

use crate::lib_common::*;

pub struct Client {
    pub uid: u32,
    pub k_r: Key<Aes256Gcm>, // Symmetric key shared with the receiver
}

pub struct Moderator {
    pub k_m: [u8; 32]
}

// Client operations

impl Client {
    pub fn new(k_r: Key<Aes256Gcm>) -> Client {
        Client {
            uid: rand::random(),
            k_r: k_r,
        }
    }

    pub fn send(message: &str, k_r: Key<Aes256Gcm>) -> (Vec<u8>, Vec<u8>) {
        let mut k_f: Vec<u8> = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut k_f);

        let c2 = com_commit(&k_f, message);

        let cipher = Aes256Gcm::new(&k_r);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, k_f)).expect("");
        let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let c1 = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

        (c1, c2)
    }

    pub fn read(k_r: Key<Aes256Gcm>, c1: Vec<u8>, rt: (Vec<u8>, String, Vec<u8>)) -> (String, String, (Vec<u8>, Vec<u8>), Vec<u8>) {

        let c1_obj = bincode::deserialize::<(Vec<u8>, Vec<u8>)>(&c1).unwrap();
        let ct = c1_obj.0;
        let nonce = Nonce::from_slice(&c1_obj.1);

        let cipher = Aes256Gcm::new(&k_r);
        let payload_bytes = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        let payload = bincode::deserialize::<(&str, Vec<u8>)>(&payload_bytes).unwrap();

        let (m, k_f) = payload;

        let (c2, ctx, sigma) = rt;

        // Verify franking tag
        assert!(com_open(&c2, m, &k_f));

        let rd = (k_f.to_vec(), c2);

        (m.to_string(), ctx.to_string(), rd, sigma)
    }
}

// Moderator operations

impl Moderator {
    pub fn mod_process(k_m: &[u8; 32], c2: &Vec<u8>, ctx: &str) -> Vec<u8> {
        let sigma = mac_sign(k_m, &[&c2, ctx.as_bytes()].concat());

        sigma
    }

    pub fn moderate(k_m: &[u8; 32], m: &str, ctx: &str, rd: (Vec<u8>, Vec<u8>), sigma: Vec<u8>) -> bool {
        let (k_f, c2) = rd;

        let valid_f = com_open(&c2, m, &k_f);
        let valid_r = mac_verify(k_m, &[&c2, ctx.as_bytes()].concat(), &sigma);

        valid_f && valid_r
    }

    pub fn new() -> Moderator {
        Moderator {
            k_m: mac_keygen()
        }
    }
}



// Setup Messages
pub fn test_init_messages(num_clients: usize, msg_size: usize) -> Vec<String> {
    // Prepare messages
    let mut ms: Vec<String> = Vec::with_capacity(num_clients);
    for _i in 0..num_clients {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }
    ms
}

// Clients
pub fn test_init_clients(num_clients: usize) -> Vec<Client> {
    let mut clients: Vec<Client> = Vec::with_capacity(num_clients);
    for _i in 0..num_clients {
        let k_r = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
        let client = Client::new(k_r);
        clients.push(client);
    }

    clients
}

// send()
pub fn test_send(senders: &Vec<Client>, ms: &Vec<Vec<String>>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let n: usize = senders.len();
    let mut c1c2s: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(n);
    for i in 0..n {
        let (c1, c2) = Client::send(&ms[i][0], senders[i].k_r);

        // let (c1, c2, c3) = p::Client::send(&ms[i], senders[i].k_r, &pks, n);
        c1c2s.push((c1, c2));
    }

    c1c2s
}

// mod_process
pub fn test_process(moderator: &Moderator, c1c2s: &Vec<(Vec<u8>, Vec<u8>)>) -> Vec<Vec<u8>> {
    let n: usize = c1c2s.len();
    let mut sigmas: Vec<Vec<u8>> = Vec::with_capacity(n);

    for i in 0..n {
        let (_, c2) = &c1c2s[i];
        sigmas.push(Moderator::mod_process(&moderator.k_m, &c2, CTX_STR));
    }

    sigmas
}

// receive messages
pub fn test_read(clients: &Vec<Client>, c1c2s: &Vec<(Vec<u8>, Vec<u8>)>, sigmas: &Vec<Vec<u8>>) -> Vec<(String, String, (Vec<u8>, Vec<u8>), Vec<u8>)> {
    let n: usize = c1c2s.len();
    let mut reports: Vec<(String, String, (Vec<u8>, Vec<u8>), Vec<u8>)> = Vec::with_capacity(n);

    for i in 0..n {
        let (c1, c2) = c1c2s[i].clone();
        let st = (c2, CTX_STR.to_string(), sigmas[i].clone());
        reports.push(Client::read(clients[0].k_r, c1.clone(), st.clone()));
    }

    reports
}
