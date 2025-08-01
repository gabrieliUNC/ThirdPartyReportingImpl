use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use std::mem;
use bincode;
use crate::lib_common::*;
use crate::lib_gamal as gamal;
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::distributions::DistString;
use rand::Rng;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use group::GroupEncoding;
use rand::rngs::OsRng;

type Point = CompressedRistretto;
type PublicKey = (Point, Point, Scalar);
type Ciphertext = (Point, Point);
type ProcessState = (Ciphertext, Point, Vec<u8>);
use generic_array::typenum::U12;

type ReportDoc = ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>, Scalar, Ciphertext);
type Report = ([u8; 32], Vec<u8>, Ciphertext, Vec<u8>, Vec<u8>);

// Moderator Properties
pub struct Moderator {
    pub sk_p: [u8; 32], // Mac Key shared with the Platform
    pub sk_enc: Scalar, // Moderator private key
    pub pk_enc_1: Point, // Moderator public key
    pub pk_enc_2: Point, // Moderator public key 2
    pub k1_2: Scalar // Moderator re-encryption key
}

// Moderator Implementation 
impl Moderator {
    // SetupMod(pk_reg, 1^lambda)
    pub fn new(_pk_reg: &Option<Vec<u8>>) -> Moderator {
        let keys = gamal::elgamal_keygen();
        let keys2 = gamal::elgamal_keygen();
        Moderator {
            sk_p: mac_keygen(),
            sk_enc: keys2.0,
            pk_enc_1: keys.1.compress(),
            pk_enc_2: keys2.1.compress(),
            k1_2: keys2.0 * keys.0.invert() // sk2 / sk1
        }
    }

    pub fn moderate(sk_enc: &Scalar, sk_p: &[u8; 32], moderator_id: usize, message: &str, report: &Report) -> String {
        let (k_f, c2, c3_prime, ctx, sigma) = report;

        let (u, v) = c3_prime;

        let r_prime = gamal::pre_elgamal_dec(&sk_enc, &(u.decompress().unwrap(), v.decompress().unwrap()));

        // Verify committment
        assert!(com_open(&c2, message, k_f));

        // Verify signature
        assert!(mac_verify(&sk_p, &[&c2[..], &(r_prime.to_bytes().to_vec()[..]), &ctx[..]].concat(), &sigma));

        let ctx_s = std::str::from_utf8(&ctx).unwrap();
        return ctx_s.to_string();
    }
}



// Platform Properties
pub struct Platform {
    pub k_p: Option<Vec<u8>>, // Platform key
    pub k_reg: Option<Vec<u8>>, // Registration key
    pub sk_p: Vec<([u8; 32], Point)> // Vector of Moderator keys accessible to the Platform
}

// Platform Implementation
impl Platform {
    pub fn new() -> Platform {
        Platform {
            k_p: None,
            k_reg: None,
            sk_p: Vec::<([u8; 32], Point)>::new()
        }
    }


    pub fn process(_k_p: &Option<Vec<u8>>, ks: &Vec<([u8; 32], Point)>, _c1: &Vec<u8>, c2: &Vec<u8>, ad: &Point, ctx: &Vec<u8>) -> (Vec<u8>, ProcessState) {
        // Get random group element of ristretto group
        let mut r_prime = RistrettoPoint::random(&mut OsRng);
        
        let to_sign = [&c2[..], &(r_prime.to_bytes().to_vec()[..]), &ctx[..]].concat();
        
        let mut sigma_pt: Vec<u8> = Vec::<u8>::new();
        for i in 0..ks.len() {
            sigma_pt.extend(&mac_sign(&ks[i].0, &to_sign));
        }

        let epk = ad.decompress().unwrap();
        let c3 = gamal::pre_elgamal_enc(&epk, &r_prime);
        let (u, v) = c3;

        let st: ProcessState = ((u.compress(), v.compress()), *ad, ctx.clone());

        (sigma_pt, st)
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

    pub fn ccae_enc(msg_key: &Key<Aes256Gcm>, message: &str, moderator_id: u32, k_r: Scalar) -> (Vec<u8>, Vec<u8>) {
        let k_f: [u8; 32] = mac_keygen(); // franking key or r in H(m, r) for committment
        
        let c2 = com_commit(&k_f, message);

        let cipher = Aes256Gcm::new(&msg_key);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, moderator_id, k_f, k_r.to_bytes())).expect("");
        let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let c1 = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

        (c1, c2)
    }

    pub fn ccae_dec(msg_key: &Key<Aes256Gcm>, c1: &Vec<u8>, c2: &Vec<u8>) -> (String, u32, [u8; 32], Scalar) {
        let c1_obj = bincode::deserialize::<(Vec<u8>, Vec<u8>)>(&c1).unwrap();
        let ct = c1_obj.0;
        let nonce = Nonce::from_slice(&c1_obj.1);

        let cipher = Aes256Gcm::new(&msg_key);
        let payload_bytes = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        let payload = bincode::deserialize::<(&str, u32, [u8; 32], [u8; 32])>(&payload_bytes).unwrap();

        let (message, moderator_id, k_f, k_r) = payload;
        let k_r = Scalar::from_bytes_mod_order(k_r);

        // Verify committment
        assert!(com_open(&c2, message, &k_f));

        (message.to_string(), moderator_id, k_f, k_r)
    }

    pub fn send(msg_key: &Key<Aes256Gcm>, message: &str, moderator_id: u32, pk_i: &PublicKey) -> (Vec<u8>, Vec<u8>, Point) {
        let (pk1, pk2, k1_2) = pk_i;
        let s: Scalar = Scalar::random(&mut OsRng);
        let epk = &s * pk1.decompress().unwrap();
        let k_r = k1_2 * s.invert();

        let (c1, c2) = Self::ccae_enc(msg_key, message, moderator_id, k_r);       

        (c1, c2, epk.compress())
    }
    
    pub fn read(msg_key: &Key<Aes256Gcm>, pks: &Vec<PublicKey>, c1: &Vec<u8>, c2: &Vec<u8>, sigma: &Vec<u8>, st: &ProcessState) -> (String, u32, ReportDoc) {
        let (c3, epk, ctx) = st;
        let (message, moderator_id, k_f, k_r) = Self::ccae_dec(msg_key, c1, c2);

        let pk2 = pks[usize::try_from(moderator_id).unwrap()].1;

        // Ensure this message is reportable
        assert!((&k_r * epk.decompress().unwrap()) == pk2.decompress().unwrap());

        // Sigma For Chosen Moderator
        let l: usize = (moderator_id as usize) * 32;
        let r: usize = l + 32;
        let tag: Vec<u8> = sigma[l..r].to_vec();
        
        let rd: ReportDoc = (k_f, c2.to_vec(), ctx.to_vec(), tag.clone(), k_r, c3.clone());

        (message, moderator_id, rd)
    }

    pub fn report_gen(_msg: &String, rd: &ReportDoc) -> Report {
        let (k_f, c2, ctx, sigma, k_r, c3) = rd;

        let(u, v) = c3;

        let c3_prime = gamal::pre_re_enc(&(u.decompress().unwrap(), v.decompress().unwrap()), &k_r);

        let (u_prime, v_prime) = c3_prime;

        let report: Report = (*k_f, c2.clone(), (u_prime.compress(), v_prime.compress()), ctx.clone(), sigma.clone());

        report
    }



}



pub fn test_setup_platform() -> Platform {
    let platform = Platform::new();

    platform
}


// SetupMod(pk_reg, 1^lambda)
pub fn test_setup_mod(platform: &mut Platform, num_moderators: usize) -> (Vec<Moderator>, Vec<PublicKey>) {
    let mut moderators: Vec<Moderator> = Vec::with_capacity(num_moderators);
    let mut pks: Vec<PublicKey> = Vec::with_capacity(num_moderators);

    for _i in 0..num_moderators {
        let moderator = Moderator::new(&platform.k_reg);
        platform.sk_p.push((moderator.sk_p.clone(), moderator.pk_enc_2.clone()));
        pks.push((moderator.pk_enc_1.clone(), moderator.pk_enc_2.clone(), moderator.k1_2.clone()));
        moderators.push(moderator);
    }


    (moderators, pks)
}

pub fn test_setup() -> (Vec<Platform>, Vec<Vec<Moderator>>, Vec<Vec<PublicKey>>) {
    let n: usize = usize::try_from(MOD_SCALE.len()).unwrap();
    let mut platforms: Vec<Platform> = Vec::with_capacity(n);
    
    for _i in 0..n {
        platforms.push(Platform::new());
    }
    
    let mut moderators: Vec<Vec<Moderator>> = Vec::with_capacity(n);
    let mut pubs: Vec<Vec<PublicKey>> = Vec::new();

    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        let k = usize::try_from(*num_moderators).unwrap();
        let (mods, pks) = test_setup_mod(&mut platforms[i], k);
        moderators.push(mods);
        pubs.push(pks);
    }

    (platforms, moderators, pubs)
}


// Setup Clients
pub fn test_init_clients(num_clients: usize) -> Vec<Client> {
    let mut clients: Vec<Client> = Vec::with_capacity(num_clients);
    for _i in 0..num_clients {
        let client = Client::new();
        clients.push(client);
    }

    clients
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


// send(k, m, pk_i)
pub fn test_send(num_clients: usize, moderators: &Vec<Moderator>, clients: &Vec<Client>, ms: &Vec<String>, print: bool) -> Vec<(Vec<u8>, Vec<u8>, Point)> {
    let mut c1c2ad: Vec<(Vec<u8>, Vec<u8>, Point)> = Vec::with_capacity(num_clients);
    let num_moderators = moderators.len();

    // send message i to client i to be moderated by random mod
    let mut rng = thread_rng();
    for i in 0..num_clients {
        let mod_i = rng.gen_range(0..num_moderators);
        let mod_ref = &moderators[usize::try_from(mod_i).unwrap()];
        let pki: PublicKey = (mod_ref.pk_enc_1.clone(), mod_ref.pk_enc_2.clone(), mod_ref.k1_2.clone());
        let (c1, c2, ad) = Client::send(&clients[i].msg_key, &ms[i], mod_i.try_into().unwrap(), &pki);
        
        if print {
            // Additional Costs
            // (1) Commitment to the Message
            // (2) Moderator masked public key (element of G)
            // (3) commitment randomness (32 bytes)
            // (4) Scalar of G (32 bytes)
            // Moderator id (4 bytes)
            let mut send_cost: usize = mem::size_of_val(&*c2) + mem::size_of_val(&ad) + 32 + 32 + 4;

            println!("Sending communication cost: {} (bytes)", &send_cost);
        }
        c1c2ad.push((c1, c2, ad));
    }

    c1c2ad
}

// Send messages of sizes in MSG_SIZE_SCALE
// to platforms with num moderators in MOD_SCALE
pub fn test_send_variable(moderators: &Vec<Vec<Moderator>>, clients: &Vec<Client>, ms: &Vec<Vec<String>>) -> 
Vec<Vec<Vec<(Vec<u8>, Vec<u8>, Point)>>> {
    // Send messages
    let mut c1c2ad: Vec<Vec<Vec<(Vec<u8>, Vec<u8>, Point)>>> = Vec::new();
    // c1c2ad[i][j] = Encryption of message j to moderator i
    for i in 0..moderators.len() {
        let mut tmp: Vec<Vec<(Vec<u8>, Vec<u8>, Point)>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, _msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(test_send(1, &moderators[i], clients, &ms[j], false));
        }
        c1c2ad.push(tmp);
    }

    c1c2ad
}


// process(k_p, ks, c1, c2, ad, ctx)
pub fn test_process(num_clients: usize, msg_size: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>, platform: &Platform, print: bool) -> Vec<(Vec<u8>, ProcessState)> {
    let mut sigma_st: Vec<(Vec<u8>, ProcessState)> = Vec::with_capacity(num_clients);
    // Platform processes message
    for i in 0..num_clients {
        let (c1, c2, ad) = &c1c2ad[i];
        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        let (sigma, st) = Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, ad, &ctx.as_bytes().to_vec());

        sigma_st.push((sigma, st));
    }

    sigma_st
}

// Process messages of sizes in MSG_SIZE_SCALE
// and encrypt them to moderators in MOD_SCALE
pub fn test_process_variable(moderators: &Vec<Vec<Moderator>>, c1c2ad: &Vec<Vec<Vec<(Vec<u8>, Vec<u8>, Point)>>>, platforms: &Vec<Platform>) -> Vec<Vec<Vec<(Vec<u8>, ProcessState)>>> {
    // Process messages
    let mut sigma_st: Vec<Vec<Vec<(Vec<u8>, ProcessState)>>> = Vec::new();
    // sigma_st[i][j] = encrypted signature on message commitmment j to moderator i
    for i in 0..moderators.len() {
        let mut tmp: Vec<Vec<(Vec<u8>, ProcessState)>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(test_process(1, *msg_size, &c1c2ad[i][j], &platforms[i], false));
        }
        sigma_st.push(tmp);
    }

    sigma_st
}

// read(k, pks, c1, c2, sigma, st)
pub fn test_read(num_clients: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>, sigma_st: &Vec<(Vec<u8>, ProcessState)>, clients: &Vec<Client>, pks: &Vec<PublicKey>, print: bool) -> Vec<(String, u32, ReportDoc)> {
    // Receive messages
    let mut rds: Vec<(String, u32, ReportDoc)> = Vec::with_capacity(num_clients);
    // Receive message i from client i to be moderated by randomly selected moderator mod_i
    for i in 0..num_clients {
        let (c1, c2, _ad) = &c1c2ad[i];
        let (sigmas, st) = &sigma_st[i];
        let (message, ad, rd) = Client::read(&clients[i].msg_key, &pks, &c1, &c2, &sigmas, &st);

        if print {
            let (_, epk, __) = st.clone();
            let (k_f, c2, _ctx, sigma, k_r, c3): ReportDoc = rd.clone();
            let (u, v) = c3;
            // Receiving communication cost
            // (1) commitment randomness (32 bytes)
            // (2) commitment
            // (3) sigmas (32 bytes * # moderators)
            // (4) epk
            // (5) el gamal ct
            // (6) Scalar of G
            // (7) moderator id (4 bytes)

            let mut recv_cost: usize = mem::size_of_val(&epk) + mem::size_of_val(&k_f) + mem::size_of_val(&*c2) + mem::size_of_val(&u) + mem::size_of_val(&v) + mem::size_of_val(&k_r) + mem::size_of_val(&**sigmas) + mem::size_of_val(&ad);

            println!("Receiving communication cost: {} (bytes)", &recv_cost);


            // Storage communication cost
            // (1) commitment randomness (32 bytes)
            // (2) commitment
            // (3) sigma (32 bytes)
            // (4) moderator id
            // (5) el gamal ct
            // (6) Scalar of G

            let mut storage_cost: usize = mem::size_of_val(&ad) + mem::size_of_val(&k_f) + mem::size_of_val(&*c2) + mem::size_of_val(&u) + mem::size_of_val(&v) + mem::size_of_val(&k_r) + mem::size_of_val(&*sigma);
            println!("Storage communication cost: {} (bytes)", &storage_cost);
        }
        rds.push((message, ad, rd));
    }

    rds
}

pub fn test_report(num_clients: usize, rds: &Vec<(String, u32, ReportDoc)>, print: bool) -> Vec<(String, u32, Report)> {
    let mut reports: Vec<(String, u32, Report)> = Vec::with_capacity(num_clients);

    for i in 0..num_clients {
        let (message, mod_id, rd) = &rds[i];
        let report = Client::report_gen(&message, &rd);


        reports.push((message.clone(), *mod_id, report));
    }

    reports
}


// moderate(sk_mod, sk_p, m, report)
pub fn test_moderate(num_clients: usize, reports: &Vec<(String, u32, Report)>, moderators: &Vec<Moderator>, print: bool) {
    // Moderate messages
    for i in 0..num_clients {
        let (message, moderator_id, report) = &reports[i];
        let j = usize::try_from(*moderator_id).unwrap();
        let ctx = Moderator::moderate(&moderators[j].sk_enc, &moderators[j].sk_p, j, &message, &report);
        if print {
            // Judging cost is inputs to moderate
            // (1) commitment
            // (2) commitment randomness (32 bytes)
            // (3) sigma
            // (4) el gamal ct

            let (k_f, c2, c3_prime, ctx, sigma) = report.clone();
            let (u, v) = c3_prime.clone();
            let mut cost: usize = mem::size_of_val(&k_f) + mem::size_of_val(&*c2) + mem::size_of_val(&u) + mem::size_of_val(&v) + mem::size_of_val(&*sigma);
            println!("Moderation communication cost: {} (bytes)", &cost);
        }
    }

}
