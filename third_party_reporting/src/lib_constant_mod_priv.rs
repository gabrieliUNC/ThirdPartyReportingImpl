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
use curve25519_dalek::scalar::Scalar;

use blstrs as blstrs;
use group::Curve;
use group::prime::PrimeCurveAffine;
use ff::Field;
use crate::lib_blst as bls;


type PublicKey = (Point, Point, Scalar, blstrs::G2Affine);
type Point = RistrettoPoint;
type Ciphertext = ((Point, Point), Vec<u8>, Nonce<U12>);
use generic_array::typenum::U12;


// Moderator Properties
pub struct Moderator {
    pub sk_p: [u8; 32], // Mac Key shared with the Platform
    pub sk_enc: Scalar, // Moderator private key
    pub pk_enc_1: Point, // Moderator public key
    pub pk_enc_2: Point, // Moderator public key 2
    pub k1_2: Scalar, // Moderator re-encryption key
    pub k: blstrs::Scalar, // Moderator group scalar secret key
    pub pk_proc: blstrs::G2Affine // Moderator group 2 public key
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
        let pk = (pk_reg * sk).to_affine();
        Moderator {
            sk_p: mac_keygen(),
            sk_enc: keys2.0,
            pk_enc_1: keys.1,
            pk_enc_2: keys2.1,
            k1_2: keys2.0 * keys.0.invert(), // sk2 / sk1
            k: sk,
            pk_proc: pk
        }
    }

    pub fn moderate(sk_enc: &Scalar, k: &blstrs::Scalar, _sk_p: &[u8; 32], _moderator_id: usize, message: &str, report: &(Vec<u8>, [u8; 32], Vec<u8>, blstrs::Gt, Ciphertext)) -> String {
        let (c2, r, ctx, sigma_prime, c3_prime) = report;
        let (el_gamal_ct, r_ct, nonce) = c3_prime;

        let r_prime = gamal::pre_dec(sk_enc, &(*el_gamal_ct, r_ct.to_vec()), nonce);

        // Remove r' from sigma
        let r_prime = blstrs::Scalar::from_bytes_le(&r_prime.try_into().unwrap()).unwrap();
        let r_prime_inv = r_prime.invert().unwrap();

        let sigma = sigma_prime * r_prime_inv;

        // Compute H(c2, ctx)
        let hashed_g1 = blstrs::G1Projective::hash_to_curve(&[&c2[..], &ctx[..]].concat(), &[], &[]);
        // H(c2, ctx)^k
        let hashed_g1 = (hashed_g1 * (*k)).to_affine();
        
        let maybe_sigma = blstrs::pairing(&hashed_g1, &blstrs::G2Affine::generator());

        // Verify committment
        let k_f = r;
        assert!(com_open(&c2, message, k_f));

        // Verify signature
        assert!(sigma == maybe_sigma);

        let ctx_s = std::str::from_utf8(&ctx).unwrap();
        return ctx_s.to_string();
    }
}



// Platform Properties
pub struct Platform {
    pub k_p: blstrs::Scalar, // Platform key
    pub k_reg: blstrs::G2Affine, // Registration key
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
            k_reg: pk,
            sk_p: Vec::<([u8; 32], PublicKey)>::new()
        }
    }


    pub fn process(k_p: &blstrs::Scalar, _ks: &Vec<([u8; 32], PublicKey)>, _c1: &Vec<u8>, c2: &Vec<u8>, ad: &(Point, blstrs::G2Affine), ctx: &Vec<u8>) -> (blstrs::Gt, (Ciphertext, Point, blstrs::G2Affine, Vec<u8>)) {
        let (pk_a, pk_b) = ad;
        
        let rng = thread_rng();
        let r_prime = blstrs::Scalar::random(rng);


        // Compute H(c2, ctx)
        let hashed_g1 = blstrs::G1Projective::hash_to_curve(&[&c2[..], &ctx[..]].concat(), &[], &[]);
        // H(c2, ctx)^k_p
        let hashed_g1 = hashed_g1 * k_p;
        // H(c2, ctx)^(k_p * r')
        let hashed_g1 = hashed_g1 * r_prime;
            

        // Compute pairing
        let sigma: blstrs::Gt = blstrs::pairing(&hashed_g1.to_affine(), pk_b);

        // PRE Scheme
        let c3 = gamal::pre_enc(pk_a, &r_prime.to_bytes_le().to_vec());


        (sigma, (c3, *pk_a, *pk_b, ctx.clone()))
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

    pub fn ccae_enc(msg_key: &Key<Aes256Gcm>, message: &str, moderator_id: u32, k_r: Scalar, t: &[u8; 32], k_f: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let c2 = com_commit(k_f, message);

        let cipher = Aes256Gcm::new(&msg_key);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, moderator_id, t, k_r.to_bytes())).expect("");
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

        let (message, moderator_id, t, k_r) = payload;
        let k_r = Scalar::from_bytes_mod_order(k_r);

        // Retrieve franking key
        let (_s, k_f) = mac_prg(&t);

        // Verify committment
        assert!(com_open(&c2, message, &k_f));

        (message.to_string(), moderator_id, t, k_r)
    }

    pub fn send(msg_key: &Key<Aes256Gcm>, message: &str, moderator_id: u32, pk_i: &PublicKey) -> (Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine)) {
        let (pk1, pk2, k1_2, pk_proc) = pk_i;

        // PRG operations
        let t = mac_keygen();
        let (s, r) = mac_prg(&t);

        // El gamal proxy re-encryption
        let s_scalar: Scalar = Scalar::from_bytes_mod_order(s.try_into().unwrap());
        let pk_a: Point = &s_scalar * pk1;
        let k_r: Scalar = k1_2 * s_scalar.invert();

        assert!((&k_r * pk_a) == *pk2);


        // Bls Signature
        let r_scal: blstrs::Scalar = bls::new_blstrs_scalar(&r.clone().try_into().unwrap());
        let pk_b = (pk_proc * r_scal).to_affine();

        let (c1, c2) = Self::ccae_enc(msg_key, message, moderator_id, k_r, &t.try_into().unwrap(), &r.try_into().unwrap());       

        (c1, c2, (pk_a, pk_b))
    }
  
    pub fn read(msg_key: &Key<Aes256Gcm>, pks: &Vec<PublicKey>, c1: &Vec<u8>, c2: &Vec<u8>, sigma: &blstrs::Gt, st: &(Ciphertext, Point, blstrs::G2Affine, Vec<u8>)) -> (String, u32, (Vec<u8>, [u8; 32], Vec<u8>, blstrs::Gt, Ciphertext)) {
        let (c3, pk_a, pk_b, ctx) = st;
        let (message, moderator_id, t, k_r) = Self::ccae_dec(msg_key, c1, c2);

        // Derive randomness
        let (_s, r) = mac_prg(&t);

        let (_pk1, pk2, _k1_2, pk_proc) = pks[usize::try_from(moderator_id).unwrap()];


        // Ensure this message is reportable
        assert!((&k_r * pk_a) == pk2);


        let r_scal = bls::new_blstrs_scalar(&r.clone().try_into().unwrap());
        assert!((pk_proc * r_scal).to_affine() == *pk_b);
        
        // compute inverse of r
        let r_inv: blstrs::Scalar = bls::new_blstrs_scalar(&r.clone().try_into().unwrap()).invert().unwrap();
        let sigma_prime: blstrs::Gt = sigma * r_inv;

        // PRE Re-Encryption
        let (ct, sym_ct, nonce) = c3;
        let c3_prime = gamal::pre_re_enc(&ct, &k_r);

        let report: (Vec<u8>, [u8; 32], Vec<u8>, blstrs::Gt, Ciphertext) = (c2.clone(), r.try_into().unwrap(), ctx.to_vec(), sigma_prime, (c3_prime, sym_ct.to_vec(), *nonce));


        (message, moderator_id, report)
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
pub fn test_send(num_clients: usize, moderators: &Vec<Moderator>, clients: &Vec<Client>, ms: &Vec<String>, print: bool) -> Vec<(Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine))> {
    let mut c1c2ad: Vec<(Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine))> = Vec::with_capacity(num_clients);
    let num_moderators = moderators.len();

    // send message i to client i to be moderated by random mod
    let mut rng = thread_rng();
    for i in 0..num_clients {
        let mod_i = rng.gen_range(0..num_moderators);
        let mod_ref = &moderators[usize::try_from(mod_i).unwrap()];
        let pki: PublicKey = (mod_ref.pk_enc_1.clone(), mod_ref.pk_enc_2.clone(), mod_ref.k1_2.clone(), mod_ref.pk_proc.clone());
        let (c1, c2, ad) = Client::send(&clients[i].msg_key, &ms[i], mod_i.try_into().unwrap(), &pki);
        
        if print {
            println!("Sent message: {}", &ms[i]);
        }
        c1c2ad.push((c1, c2, ad));
    }

    c1c2ad
}


// Send messages of sizes in MSG_SIZE_SCALE
// to platforms with num moderators in MOD_SCALE
pub fn test_send_variable(moderators: &Vec<Vec<Moderator>>, clients: &Vec<Client>, ms: &Vec<Vec<String>>) -> 
Vec<Vec<Vec<(Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine))>>> {
    // Send messages
    let mut c1c2ad: Vec<Vec<Vec<(Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine))>>> = Vec::new();
    // c1c2ad[i][j] = Encryption of message j to moderator i
    for i in 0..moderators.len() {
        let mut tmp: Vec<Vec<(Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine))>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, _msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(test_send(1, &moderators[i], clients, &ms[j], false));
        }
        c1c2ad.push(tmp);
    }

    c1c2ad
}


// process(k_p, ks, c1, c2, ad, ctx)
pub fn test_process(num_clients: usize, msg_size: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine))>, platform: &Platform, print: bool) -> Vec<(blstrs::Gt, (Ciphertext, Point, blstrs::G2Affine, Vec<u8>))> {
    let mut sigma_st: Vec<(blstrs::Gt, (Ciphertext, Point, blstrs::G2Affine, Vec<u8>))> = Vec::with_capacity(num_clients);
    // Platform processes message
    for i in 0..num_clients {
        let (c1, c2, ad) = &c1c2ad[i];
        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        if print {
            println!("Adding context: {}", ctx);
        }
        let (sigma, st) = Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, ad, &ctx.as_bytes().to_vec());

        sigma_st.push((sigma, st));
    }

    sigma_st
}


// Process messages of sizes in MSG_SIZE_SCALE
// and encrypt them to moderators in MOD_SCALE
pub fn test_process_variable(moderators: &Vec<Vec<Moderator>>, c1c2ad: &Vec<Vec<Vec<(Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine))>>>, platforms: &Vec<Platform>) -> Vec<Vec<Vec<(blstrs::Gt, (Ciphertext, Point, blstrs::G2Affine, Vec<u8>))>>> {
    // Process messages
    let mut sigma_st: Vec<Vec<Vec<(blstrs::Gt, (Ciphertext, Point, blstrs::G2Affine, Vec<u8>))>>> = Vec::new();
    // sigma_st[i][j] = encrypted signature on message commitmment j to moderator i
    for i in 0..moderators.len() {
        let mut tmp: Vec<Vec<(blstrs::Gt, (Ciphertext, Point, blstrs::G2Affine, Vec<u8>))>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(test_process(1, *msg_size, &c1c2ad[i][j], &platforms[i], false));
        }
        sigma_st.push(tmp);
    }

    sigma_st
}



// read(k, pks, c1, c2, sigma, st)
pub fn test_read(num_clients: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine))>, sigma_st: &Vec<(blstrs::Gt, (Ciphertext, Point, blstrs::G2Affine, Vec<u8>))>, clients: &Vec<Client>, pks: &Vec<PublicKey>, print: bool) -> Vec<(String, u32, (Vec<u8>, [u8; 32], Vec<u8>, blstrs::Gt, Ciphertext))> {
    // Receive messages
    let mut reports: Vec<(String, u32, (Vec<u8>, [u8; 32], Vec<u8>, blstrs::Gt, Ciphertext))> = Vec::with_capacity(num_clients);
    // Receive message i from client i to be moderated by randomly selected moderator mod_i
    for i in 0..num_clients {
        let (c1, c2, _ad) = &c1c2ad[i];
        let (sigma, st) = &sigma_st[i];
        let (message, ad, report) = Client::read(&clients[i].msg_key, &pks, &c1, &c2, &sigma, &st);

        if print {
            println!("Received message: {}", message);
        }
        reports.push((message, ad, report));
    }

    reports
}


// moderate(sk_mod, sk_p, m, report)
pub fn test_moderate(num_clients: usize, reports: &Vec<(String, u32, (Vec<u8>, [u8; 32], Vec<u8>, blstrs::Gt, Ciphertext))>, moderators: &Vec<Moderator>, print: bool) {
    // Moderate messages
    for i in 0..num_clients {
        let (message, moderator_id, report) = &reports[i];
        let j = usize::try_from(*moderator_id).unwrap();
        let ctx = Moderator::moderate(&moderators[j].sk_enc, &moderators[j].k, &moderators[j].sk_p, j, &message, &report);
        if print {
            println!("Moderated message successfully with context: {:?}", ctx);
        }
    }

}

