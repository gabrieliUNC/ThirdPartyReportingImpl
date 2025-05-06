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
use rand::rngs::OsRng;

pub use blstrs::{G1Affine, G2Affine, Gt, Compress, GtCompressed};
use group::{Curve, GroupEncoding};
use group::prime::PrimeCurveAffine;
use ff::Field;
use serde::ser::Serialize;


type Point = CompressedRistretto;
type PublicKey = (Point, Point, Scalar, G2Compressed);
type Ciphertext = (Point, Point);
use generic_array::typenum::U12;

type Report = (Vec<u8>, [u8; 32], Vec<u8>, blstrs::GtCompressed, Ciphertext);
type ReportDoc = (Vec<u8>, [u8; 32], Vec<u8>, G1Compressed, G2Compressed, Scalar, Ciphertext);
type State = (Ciphertext, Point, Vec<u8>);

#[derive(Clone)]
pub struct G1Compressed {
    point: [u8; 48]
}
#[derive(Clone)]
pub struct G2Compressed {
    point: [u8; 96]
}



// Moderator Properties
pub struct Moderator {
    pub sk_p: [u8; 32], // Mac Key shared with the Platform
    pub sk_enc: Scalar, // Moderator private key
    pub pk_enc_1: Point, // Moderator public key
    pub pk_enc_2: Point, // Moderator public key 2
    pub k1_2: Scalar, // Moderator re-encryption key
    pub k: blstrs::Scalar, // Moderator group scalar secret key
    pub pk_proc: G2Compressed // Moderator group 2 public key
}

// Moderator Implementation 
impl Moderator {
    // SetupMod(pk_reg, 1^lambda)
    pub fn new(pk_reg: &blstrs::G2Affine) -> Moderator {
        let keys = gamal::elgamal_keygen();
        let keys2 = gamal::elgamal_keygen();

        let rng = thread_rng();
        // k <- R
        let sk = blstrs::Scalar::random(rng);

        // k_reg^k
        let pk: G2Compressed = G2Compressed {
            point: (pk_reg * sk).to_compressed()
        };
        Moderator {
            sk_p: mac_keygen(),
            sk_enc: keys2.0,
            pk_enc_1: keys.1.compress(),
            pk_enc_2: keys2.1.compress(),
            k1_2: keys2.0 * keys.0.invert(), // sk2 / sk1
            k: sk,
            pk_proc: pk
        }
    }

    pub fn moderate(sk_enc: &Scalar, k: &blstrs::Scalar, _sk_p: &[u8; 32], _moderator_id: usize, message: &str, report: &Report) -> String {
        let (c2, r, ctx, sigma_prime, c3_prime) = report;
        let (u, v) = c3_prime;

        let r_prime = gamal::pre_elgamal_dec(sk_enc, &(u.decompress().unwrap(), v.decompress().unwrap()));

        let mut r_prime_bytes: [u8; 32] = [0u8; 32];
        r_prime_bytes.copy_from_slice(&hash(&r_prime.to_bytes().to_vec()));
        let r_prime_bls_scalar = new_blstrs_scalar(r_prime_bytes);

        // Compute H(c2, ctx)
        let hashed_g1 = blstrs::G1Projective::hash_to_curve(&[&c2[..], &ctx[..]].concat(), &[], &[]);
        // H(c2, ctx)^(k*r')
        let hashed_g1 = hashed_g1 * (*k * r_prime_bls_scalar);

        let maybe_sigma = blstrs::pairing(&hashed_g1.to_affine(), &blstrs::G2Affine::generator());

        // Verify committment
        let k_f = r;
        assert!(com_open(&c2, message, k_f));

        // Verify signature
        assert!(sigma_prime.uncompress().unwrap() == maybe_sigma);

        let ctx_s = std::str::from_utf8(&ctx).unwrap();
        return ctx_s.to_string();
    }
}



// Platform Properties
pub struct Platform {
    pub k_p: blstrs::Scalar, // Platform key
    pub k_reg: G2Compressed, // Registration key
    pub sk_p: Vec<([u8; 32], PublicKey)> // Vector of Moderator keys accessible to the Platform
}

// Platform Implementation
impl Platform {
    pub fn new() -> Platform {
        let rng = thread_rng();
        // k_p <- R
        let sk = blstrs::Scalar::random(rng);

        // Get inverse for registration key
        // 1/k_p
        let sk_inv = sk.invert().unwrap();

        // g2^(1/k_p)
        let g2 = blstrs::G2Affine::generator();
        let pk = (g2 * sk_inv).to_affine();

        Platform {
            k_p: sk,
            k_reg: G2Compressed {
                point: pk.to_compressed()
            },
            sk_p: Vec::<([u8; 32], PublicKey)>::new()
        }
    }




    pub fn process(k_p: &blstrs::Scalar, _ks: &Vec<([u8; 32], PublicKey)>, _c1: &Vec<u8>, c2: &Vec<u8>, ad: &Point, ctx: &Vec<u8>) -> (G1Compressed, State) {
        let pk_a = ad;
        
        // Make RistrettoPoint to encrypt with elgamal
        let r_prime = RistrettoPoint::random(&mut OsRng);
        
        // Make random bytes for bls Scalar
        let mut r_prime_bytes: [u8; 32] = [0u8; 32];
        r_prime_bytes.copy_from_slice(&hash(&r_prime.to_bytes().to_vec()));
        let r_prime_bls_scalar = new_blstrs_scalar(r_prime_bytes);

        // Compute H(c2, ctx)
        let hashed_g1 = blstrs::G1Projective::hash_to_curve(&[&c2[..], &ctx[..]].concat(), &[], &[]);

        // H(c2, ctx)^(k_p * r')
        let sigma = hashed_g1 * (k_p * r_prime_bls_scalar);

        // PRE Scheme
        let c3 = gamal::pre_elgamal_enc(&pk_a.decompress().unwrap(), &r_prime);
        let (u, v) = c3;

        (G1Compressed { point : sigma.to_compressed() }, ((u.compress(), v.compress()), *pk_a, ctx.clone()))
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


    pub fn ccae_dec(msg_key: &Key<Aes256Gcm>, c1: &Vec<u8>, c2: &Vec<u8>) -> (String, u32, Scalar, [u8; 32]) {
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

        (message.to_string(), moderator_id, k_r, k_f)
    }

    pub fn send(msg_key: &Key<Aes256Gcm>, message: &str, moderator_id: u32, pk_i: &PublicKey) -> (Vec<u8>, Vec<u8>, Point) {
        let (pk1, pk2, k1_2, pk_proc) = pk_i;

        // El gamal proxy re-encryption
        let x = Scalar::random(&mut OsRng);
        let pk_a: Point = (&x * pk1.decompress().unwrap()).compress();
        let k_r: Scalar = k1_2 * x.invert();


        let (c1, c2) = Self::ccae_enc(msg_key, message, moderator_id, k_r);

        (c1, c2, (pk_a))
    }
  


    pub fn read(msg_key: &Key<Aes256Gcm>, pks: &Vec<PublicKey>, c1: &Vec<u8>, c2: &Vec<u8>, sigma: &G1Compressed, st: &(Ciphertext, Point, Vec<u8>)) -> (String, u32, ReportDoc) {
        let (c3, pk_a, ctx) = st;
        let (message, moderator_id, k_r, k_f) = Self::ccae_dec(msg_key, c1, c2);

        let (_pk1, pk2, _k1_2, pk_proc) = &pks[usize::try_from(moderator_id).unwrap()];


        // Ensure this message is reportable
        assert!((&k_r * pk_a.decompress().unwrap()) == pk2.decompress().unwrap());

        // Generate report documentation
        let rd: ReportDoc = (c2.clone(), k_f.clone(), ctx.clone(), sigma.clone(), 
            pk_proc.clone(), k_r, c3.clone());


        (message, moderator_id, rd)
    }


    // type Report = (Vec<u8>, [u8; 32], Vec<u8>, blstrs::Gt, Ciphertext);
    pub fn report_gen(msg: &String, rd: &ReportDoc) -> Report {
        let (c2, k_f, ctx, sigma, pk_proc, k_r, c3) = rd;
        let sigma_prime: blstrs::Gt = blstrs::pairing(&blstrs::G1Affine::from_compressed(&sigma.point).unwrap(), &blstrs::G2Affine::from_compressed(&pk_proc.point).unwrap());

        // PRE Re-Encryption
        let (u, v) = c3;
        let c3_prime = gamal::pre_re_enc(&(u.decompress().unwrap(), v.decompress().unwrap()), &k_r);
        let (u, v) = c3_prime;


        let report: Report = (c2.clone(), *k_f, ctx.to_vec(), 
            sigma_prime.compress().unwrap()
                , (u.compress(), v.compress()));


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
        let moderator = Moderator::new(&blstrs::G2Affine::from_compressed(&platform.k_reg.point).unwrap());
        platform.sk_p.push((moderator.sk_p.clone(), (moderator.pk_enc_1.clone(), moderator.pk_enc_2.clone(), moderator.k1_2.clone(), moderator.pk_proc.clone())));
        pks.push((moderator.pk_enc_1.clone(), moderator.pk_enc_2.clone(), moderator.k1_2.clone(), moderator.pk_proc.clone()));
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
        let pki: PublicKey = (mod_ref.pk_enc_1.clone(), mod_ref.pk_enc_2.clone(), mod_ref.k1_2.clone(), mod_ref.pk_proc.clone());
        let (c1, c2, ad) = Client::send(&clients[i].msg_key, &ms[i], mod_i.try_into().unwrap(), &pki);
        
        if print {
            // Additional Costs
            // (1) Commitment to the Message
            // (2) Moderator masked public key (element of G)
            // (3) 32 byte commitment randomness
            let mut cost: usize = mem::size_of_val(&*c2) + mem::size_of_val(&ad) + 32;

            println!("Sent message: {} with communication cost: {}", &ms[i], &cost);
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


// process(k_p, ks, c1, c2, ad, ctx) -> (G1, State)
pub fn test_process(num_clients: usize, msg_size: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>, platform: &Platform, print: bool) -> Vec<(G1Compressed, State)> {
    let mut sigma_st: Vec<(G1Compressed, State)> = Vec::with_capacity(num_clients);
    // Platform processes message
    for i in 0..num_clients {
        let (c1, c2, ad) = &c1c2ad[i];
        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        let (sigma, st) = Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, ad, &ctx.as_bytes().to_vec());


        if print {
            // Additional Costs
            // (1) Platform signature (element of G1Affine)
            // (2) epk (element of G)
            // (3) c3 (proxy re-encryption el-gamal ct of randomness)
            let mut cost: usize = mem::size_of_val(&sigma);

            let (c3, epk, ctx) = st.clone();
            
            cost += mem::size_of_val(&epk);

            let (u, v) = c3;
            cost += mem::size_of_val(&u) + mem::size_of_val(&v);

            println!("Adding context: {:?} with cost: {}", String::from_utf8(ctx).unwrap(), &cost);
        }

        sigma_st.push((sigma, st));
    }

    sigma_st
}


// Process messages of sizes in MSG_SIZE_SCALE
// and encrypt them to moderators in MOD_SCALE
pub fn test_process_variable(moderators: &Vec<Vec<Moderator>>, c1c2ad: &Vec<Vec<Vec<(Vec<u8>, Vec<u8>, Point)>>>, platforms: &Vec<Platform>) -> Vec<Vec<Vec<(G1Compressed, State)>>> {
    // Process messages
    let mut sigma_st: Vec<Vec<Vec<(G1Compressed, State)>>> = Vec::new();
    // sigma_st[i][j] = encrypted signature on message commitmment j to moderator i
    for i in 0..moderators.len() {
        let mut tmp: Vec<Vec<(G1Compressed, State)>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(test_process(1, *msg_size, &c1c2ad[i][j], &platforms[i], false));
        }
        sigma_st.push(tmp);
    }

    sigma_st
}



// read(k, pks, c1, c2, sigma, st)
pub fn test_read(num_clients: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>, sigma_st: &Vec<(G1Compressed, State)>, clients: &Vec<Client>, pks: &Vec<PublicKey>, print: bool) -> Vec<(String, u32, ReportDoc)> {
    // Receive messages
    let mut reports: Vec<(String, u32, ReportDoc)> = Vec::with_capacity(num_clients);
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
            // (4) platform signature (element of G1Affine)
            // (5) ke_2 (Scalar)
            // (6) pk_proc (PLatform mod-secret in G2Affine)
            // (7) c3 (proxy re-encryption of randonness)
            
            let mut cost: usize = mem::size_of_val(&ad);
            
            // ReportDoc cost
            let (c2, k_f, ctx, sigma, pk_proc, k_r, c3) = report.clone();
            
            cost += mem::size_of_val(&k_f);
            cost += mem::size_of_val(&*c2);
            cost += mem::size_of_val(&sigma);
            cost += mem::size_of_val(&k_r);
            cost += mem::size_of_val(&pk_proc.point);

            let (u, v) = c3;
            cost += mem::size_of_val(&u) + mem::size_of_val(&v);


            println!("Received message: {} with cost: {}", message, cost);
        }

        reports.push((message, ad, report));
    }

    reports
}

pub fn test_report(num_clients: usize, report_docs: &Vec<(String, u32, ReportDoc)>, print: bool) -> Vec<(String, u32, Report)> {
    let mut reports: Vec<(String, u32, Report)> = Vec::with_capacity(num_clients);
    for i in 0..num_clients {
        let (message, moderator_id, rd) = &report_docs[i];
        let report = Client::report_gen(message, rd);

        if print {
            // Additional Costs
            // (1) randomness for commitment
            // (2) commitment to message
            // (3) pairing signature (sigma' element of Gt)
            // (4) proxy re-encryption of randomness

            let (c2, k_f, ctx, sigma_prime, c3_prime) = report.clone();
            let mut cost: usize = mem::size_of_val(&k_f);
            
            cost += mem::size_of_val(&*c2);
            cost += mem::size_of_val(&sigma_prime);

            let (u, v) = c3_prime;
            cost += mem::size_of_val(&u) + mem::size_of_val(&v);


            println!("Generated report for message: {} with cost: {}", message, &cost);
        }

        reports.push((message.clone(), *moderator_id, report));
    }

    reports
}


// moderate(sk_mod, sk_p, m, report)
pub fn test_moderate(num_clients: usize, reports: &Vec<(String, u32, Report)>, moderators: &Vec<Moderator>, print: bool) {
    // Moderate messages
    for i in 0..num_clients {
        let (message, moderator_id, report) = &reports[i];
        let j = usize::try_from(*moderator_id).unwrap();
        let ctx = Moderator::moderate(&moderators[j].sk_enc, &moderators[j].k, &moderators[j].sk_p, j, &message, &report);
        if print {
            println!("Moderated message successfully with context: {:?} with cost: {}", ctx, CTX_LEN);
        }
    }

}

