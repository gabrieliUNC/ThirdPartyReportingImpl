use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use bincode;
use crate::lib_common::*;
use crate::lib_gamal as gamal;
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::distributions::DistString;
use rand::Rng;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use std::mem;
use group::*;
use sha2::{Sha512, Digest};

//type Point = RistrettoPoint;
type Point = CompressedRistretto;
type Ciphertext = (Point, Point);
use generic_array::typenum::U12;

type Report = ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext);

// Moderator Properties
pub struct Moderator {
    pub sk_p: [u8; 64], // Mac Key shared with the Platform
    pub sk_enc: Scalar, // Moderator private key
    pub pk_enc: Point // Moderator public key
}

// Moderator Implementation 
impl Moderator {
    // SetupMod(pk_reg, 1^lambda)
    pub fn new(_pk_reg: &Option<Vec<u8>>) -> Moderator {
        let keys = gamal::elgamal_keygen();
        Moderator {
            sk_p: mac_64_keygen(),
            sk_enc: keys.0,
            pk_enc: keys.1.compress()
        }
    }

    pub fn moderate(sk_enc: &Scalar, sk_p: &[u8; 64], message: &str, report: &([u8; 32], Vec<u8>, Vec<u8>, Ciphertext)) -> String {
        let (k_f, c2, ctx, ct) = report;

        let (u, v) = ct;
        let sigma_pt = gamal::elgamal_dec(sk_enc, &(u.decompress().unwrap(), v.decompress().unwrap())).to_bytes();

        // Verify committment
        assert!(com_open(&c2, message, k_f));

        // Verify Point
        let mut maybe_sigma = mac_64_sign(&sk_p, &[&c2[..], &ctx[..]].concat());
        // Point encrypt
        let maybe_sigma = RistrettoPoint::hash_from_bytes::<Sha512>(&maybe_sigma).to_bytes();

        // Verify Signature
        assert!(maybe_sigma == sigma_pt);

        let ctx_s = std::str::from_utf8(&ctx).unwrap();
        return ctx_s.to_string();
    }
}



// Platform Properties
pub struct Platform {
    pub k_p: Option<Vec<u8>>, // Platform key
    pub k_reg: Option<Vec<u8>>, // Registration key
    pub sk_p: Vec<([u8; 64], Point)> // Vector of Moderator keys accessible to the Platform
}

// Platform Implementation
impl Platform {
    pub fn new() -> Platform {
        Platform {
            k_p: None,
            k_reg: None,
            sk_p: Vec::<([u8; 64], Point)>::new()
        }
    }

    pub fn setup_platform(&mut self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        self.k_p = None;
        self.k_reg = None;

        (self.k_p.clone(), self.k_reg.clone())
    }

    pub fn process(_k_p: &Option<Vec<u8>>, ks: &Vec<([u8; 64], Point)>, _c1: &Vec<u8>, c2: &Vec<u8>, ad: u32, ctx: &Vec<u8>) -> (Ciphertext, (Vec<u8>, u32)) {
        let moderator_id: usize = ad.try_into().unwrap();
        let (mac_key_i, mod_pk_i) = &ks[moderator_id];

        let mut sigma_pt = mac_64_sign(&mac_key_i, &[&c2[..], &ctx[..]].concat());

        // Point encrypt
        let sigma_point = RistrettoPoint::hash_from_bytes::<Sha512>(&sigma_pt);
        let (u, v) = gamal::elgamal_enc(&mod_pk_i.decompress().unwrap(), &sigma_point);


        ((u.compress(), v.compress()), (ctx.to_vec(), ad))
    }

}


// Client Properties
pub struct Client {
    pub msg_key: Key<Aes256Gcm> // Symmetric key used to encrypt messages between sender and
}

// Client Implementation
impl Client {
    pub fn new() -> Client {
        Client {
            msg_key: Aes256Gcm::generate_key(aes_gcm::aead::OsRng)
        }
    }

    pub fn ccae_enc(msg_key: &Key<Aes256Gcm>, message: &str) -> (Vec<u8>, Vec<u8>) {
        let k_f: [u8; 32] = mac_keygen(); // franking key or r in H(m, r) for committment
        
        let c2 = com_commit(&k_f, message);

        let cipher = Aes256Gcm::new(&msg_key);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, k_f)).expect("");
        let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let c1 = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

        (c1, c2)
    }

    pub fn ccae_dec(msg_key: &Key<Aes256Gcm>, c1: &Vec<u8>, c2: &Vec<u8>) -> (String, [u8; 32]) {
        let c1_obj = bincode::deserialize::<(Vec<u8>, Vec<u8>)>(&c1).unwrap();
        let ct = c1_obj.0;
        let nonce = Nonce::from_slice(&c1_obj.1);

        let cipher = Aes256Gcm::new(&msg_key);
        let payload_bytes = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        let payload = bincode::deserialize::<(&str, [u8; 32])>(&payload_bytes).unwrap();

        let (message, k_f) = payload;

        // Verify committment
        assert!(com_open(&c2, message, &k_f));

        (message.to_string(), k_f)
    }

    pub fn send(msg_key: &Key<Aes256Gcm>, message: &str, moderator_id: u32) -> (Vec<u8>, Vec<u8>, u32) {
        let (c1, c2) = Self::ccae_enc(msg_key, message);       

        (c1, c2, moderator_id)
    }
    
    pub fn read(msg_key: &Key<Aes256Gcm>, pks: &Vec<Point>, c1: &Vec<u8>, c2: &Vec<u8>, sigma: &Ciphertext, st: &(Vec<u8>, u32)) -> (String, u32, Report) {
        let (ctx, ad) = st;

        let (message, k_f) = Self::ccae_dec(msg_key, c1, c2);

        let mod_pk_i = pks[*ad as usize];

        let rd: Report = (k_f, c2.clone(), ctx.clone(), sigma.clone());


        (message, *ad, rd)
    }

    pub fn report_gen(_msg: &String, rd: &Report) -> Report {
        let report = rd;

        report.clone()
    }
}


// SetupPlatform(1^lambda)
pub fn test_basic_setup_platform() -> Platform {
    let platform = Platform::new();

    platform
}

// SetupMod(pk_reg, 1^lambda)
pub fn test_basic_setup_mod(platform: &mut Platform, num_moderators: usize) -> (Vec<Moderator>, Vec<Point>) {
    let mut moderators: Vec<Moderator> = Vec::with_capacity(num_moderators);
    let mut pks: Vec<Point> = Vec::with_capacity(num_moderators);

    for _i in 0..num_moderators {
        let moderator = Moderator::new(&platform.k_reg);
        platform.sk_p.push((moderator.sk_p.clone(), moderator.pk_enc.clone()));
        pks.push(moderator.pk_enc.clone());
        moderators.push(moderator);
    }


    (moderators, pks)
}


pub fn test_setup() -> (Vec<Platform>, Vec<Vec<Moderator>>, Vec<Vec<Point>>) {
    let n: usize = usize::try_from(MOD_SCALE.len()).unwrap();
    let mut platforms: Vec<Platform> = Vec::with_capacity(n);
    
    for _i in 0..n {
        platforms.push(Platform::new());
    }
    
    let mut moderators: Vec<Vec<Moderator>> = Vec::with_capacity(n);
    let mut pubs: Vec<Vec<Point>> = Vec::new();

    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        let k = usize::try_from(*num_moderators).unwrap();
        let (mods, pks) = test_basic_setup_mod(&mut platforms[i], k);
        moderators.push(mods);
        pubs.push(pks);
    }

    (platforms, moderators, pubs)
}

// Setup Clients
pub fn test_basic_init_clients(num_clients: usize) -> Vec<Client> {
    let mut clients: Vec<Client> = Vec::with_capacity(num_clients);
    for _i in 0..num_clients {
        let client = Client::new();
        clients.push(client);
    }

    clients
}
// Setup Messages
pub fn test_basic_init_messages(num_clients: usize, msg_size: usize) -> Vec<String> {
    // Prepare messages
    let mut ms: Vec<String> = Vec::with_capacity(num_clients);
    for _i in 0..num_clients {
        let m = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        ms.push(m);
    }
    ms
}

// send(k, m, pk_i)
pub fn test_basic_send(num_clients: usize, num_moderators: usize, clients: &Vec<Client>, ms: &Vec<String>, print: bool) -> Vec<(Vec<u8>, Vec<u8>, u32)> {

    let mut c1c2ad: Vec<(Vec<u8>, Vec<u8>, u32)> = Vec::with_capacity(num_clients);
    // send message i to client i to be moderated by random mod
    let mut rng = thread_rng();
    for i in 0..num_clients {
        let mod_i = rng.gen_range(0..num_moderators);
        let (c1, c2, ad) = Client::send(&clients[i].msg_key, &ms[i], mod_i.try_into().unwrap());

        if print {
            // Additional Costs
            // (1) Commitment randomness
            // (2) Commitment to the Message
            // (3) Moderator id
            let mut cost: usize = 32 + mem::size_of_val(&*c2) + mem::size_of_val(&ad);

            println!("Sent message: {} with communication cost: {}", &ms[i], &cost);
        }
        c1c2ad.push((c1, c2, ad));
    }

    c1c2ad
}


// Send messages of sizes in MSG_SIZE_SCALE
// to platforms with num moderators in MOD_SCALE
pub fn test_send_variable(clients: &Vec<Client>, ms: &Vec<Vec<String>>) -> 
Vec<Vec<Vec<(Vec<u8>, Vec<u8>, u32)>>> {
    // Send messages
    let mut c1c2ad: Vec<Vec<Vec<(Vec<u8>, Vec<u8>, u32)>>> = Vec::new();
    // c1c2ad[i][j] = Encryption of message j to moderator i
    for (_i, num_moderators) in MOD_SCALE.iter().enumerate() {
        let mut tmp: Vec<Vec<(Vec<u8>, Vec<u8>, u32)>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, _msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(test_basic_send(1, *num_moderators, clients, &ms[j], false));
        }
        c1c2ad.push(tmp);
    }

    c1c2ad
}

// process(k_p, ks, c1, c2, ad, ctx)
pub fn test_basic_process(num_clients: usize, msg_size: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>, platform: &Platform, print: bool) -> Vec<(Ciphertext, (Vec<u8>, u32))> {

    let mut sigma_st: Vec<(Ciphertext, (Vec<u8>, u32))> = Vec::with_capacity(num_clients);
    // Platform processes message
    for i in 0..num_clients {
        let (c1, c2, ad) = &c1c2ad[i];
        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        let (sigma, st) = Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, *ad, &(ctx.as_bytes().to_vec()));


        if print {
            // Additional Cost
            // (1) Platform signature
            // (2) Moderator id
            let (ctx, ad) = st.clone();
            let (u, v) = sigma.clone();
            let mut cost = mem::size_of_val(&u) + mem::size_of_val(&v) + mem::size_of_val(&ad);

            println!("Adding context: {:?} with communication cost: {}", String::from_utf8(ctx).unwrap(), &cost);
        }

        sigma_st.push((sigma, st));
    }

    sigma_st
}


// Process messages of sizes in MSG_SIZE_SCALE
// and encrypt them to moderators in MOD_SCALE
pub fn test_process_variable(moderators: &Vec<Vec<Moderator>>, c1c2ad: &Vec<Vec<Vec<(Vec<u8>, Vec<u8>, u32)>>>, platforms: &Vec<Platform>) -> Vec<Vec<Vec<(Ciphertext, (Vec<u8>, u32))>>> {
    // Process messages
    let mut sigma_st: Vec<Vec<Vec<(Ciphertext, (Vec<u8>, u32))>>> = Vec::new();
    // sigma_st[i][j] = encrypted signature on message commitmment j to moderator i
    for i in 0..moderators.len() {
        let mut tmp: Vec<Vec<(Ciphertext, (Vec<u8>, u32))>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(test_basic_process(1, *msg_size, &c1c2ad[i][j], &platforms[i], false));
        }
        sigma_st.push(tmp);
    }

    sigma_st
}

// read(k, pks, c1, c2, sigma, st)
pub fn test_basic_read(num_clients: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>, sigma_st: &Vec<(Ciphertext, (Vec<u8>, u32))>, clients: &Vec<Client>, pks: &Vec<Point>, print: bool) -> Vec<(String, u32, Report)> {
    
    // Receive messages
    let mut rds: Vec<(String, u32, Report)> = Vec::with_capacity(num_clients);
    // Receive message i from client i to be moderated by randomly selected moderator mod_i
    for i in 0..num_clients {
        let (c1, c2, _ad) = &c1c2ad[i];
        let (sigma, st) = &sigma_st[i];
        let (message, ad, report) = Client::read(&clients[i].msg_key, &pks, &c1, &c2, &sigma, &st);

        if print {
            // Additional Costs
            // (1) Moderator id
            // (2) randomness for commitment
            // (3) commitment 
            // (4) sigma' (el-gamal ct of sigma)


            let (k_f, c2, _ctx, ct): ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext) = report.clone();

            let mut cost: usize = mem::size_of_val(&ad) + mem::size_of_val(&k_f) + mem::size_of_val(&*c2);
            let (u, v) = ct.clone();
            cost += mem::size_of_val(&u) + mem::size_of_val(&v);

            println!("Received message: {} with cost: {}", message, &cost);
        }
        rds.push((message, ad, report));
    }

    rds
}

pub fn test_report(num_clients: usize, rds: &Vec<(String, u32, Report)>, print: bool) -> Vec<(String, u32, Report)> {
    let mut reports: Vec<(String, u32, Report)> = Vec::with_capacity(num_clients);

    for i in 0..num_clients {
        let (msg, mod_id, rd) = &rds[i];
        let report = Client::report_gen(&msg, &rd);

        if print {
            // Additional Costs
            // (1) randomness for commitment
            // (2) commitment 
            // (3) sigma' (el-gamal ct of sigma)


            let (k_f, c2, _ctx, ct): ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext) = report.clone();

            let mut cost: usize = mem::size_of_val(&k_f) + mem::size_of_val(&*c2);
            let (u, v) = ct.clone();
            cost += mem::size_of_val(&u) + mem::size_of_val(&v);


            println!("Generated report for message: {} with cost: {}", msg, &cost);
        }

        reports.push((msg.clone(), *mod_id, report));
    }

    reports
}

// moderate(sk_mod, sk_p, m, report)
pub fn test_basic_moderate(num_clients: usize, reports: &Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext))>, moderators: &Vec<Moderator>, print: bool) {
    // Moderate messages
    for i in 0..num_clients {
        let (message, ad, report) = &reports[i];
        let ad = usize::try_from(*ad).unwrap();
        let ctx = Moderator::moderate(&moderators[ad].sk_enc, &moderators[ad].sk_p, &message, &report);
        if print {
            // cost is at most the size of the ctx
            // otherwise nothing if the signature does not verify
            println!("Moderated message successfully with context: {:?} and cost: {}", ctx, CTX_LEN);
        }
    }

}

