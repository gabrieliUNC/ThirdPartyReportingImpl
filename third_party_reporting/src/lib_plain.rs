use rand::RngCore;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
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

