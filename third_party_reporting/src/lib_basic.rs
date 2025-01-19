use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key
};
use bincode;
use openssl::encrypt::{Encrypter, Decrypter};
use openssl::rsa::{Rsa, Padding};
use openssl::pkey::PKey;
use openssl::pkey::{Private, Public};
use crate::lib_common::*;


// Global constants
const RSA_MODULUS: u32 = 2048;



// Moderator Properties
pub struct Moderator {
    pub sk_p: [u8; 32], // Mac Key shared with the Platform
    pub sk_mod: Rsa<Private>, // Moderator Encryption private key
    pub pk_mod: Rsa<Public> // Moderator Encryption public key
}

// Moderator Implementation 
impl Moderator {

    // SetupMod(pk_reg, 1^lambda)
    pub fn new(_pk_reg: Option<Vec<u8>>) -> Moderator {
        let rsa = Rsa::generate(RSA_MODULUS).unwrap();
        let pkey = PKey::from_rsa(rsa.clone()).unwrap();
        Moderator {
            sk_p: mac_keygen(),
            sk_mod: rsa,
            pk_mod: Rsa::public_key_from_pem(&pkey.public_key_to_pem().unwrap()).unwrap()
        }
    }

    pub fn moderate(sk_mod: Rsa<Private>, sk_p: [u8; 32], message: &str, report: ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>)) -> String {
        let (k_f, c2, ctx, sigma) = report;


        let keypair = PKey::from_rsa(sk_mod).unwrap();
        let mut decrypter = Decrypter::new(&keypair).unwrap();
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        let buffer_len = decrypter.decrypt_len(&sigma).unwrap();
        let mut sigma_pt = vec![0; buffer_len];

        let len: usize = decrypter.decrypt(&sigma, &mut sigma_pt).unwrap();
        sigma_pt.truncate(len);

        // Verify committment
        assert!(com_open(&c2, message, &k_f));

        // Verify signature
        assert!(mac_verify(&sk_p, &[&c2[..], &ctx[..]].concat(), sigma_pt));

        let ctx_s = std::str::from_utf8(&ctx).unwrap();
        return ctx_s.to_string();
    }
}



// Platform Properties
pub struct Platform {
    pub k_p: Option<Vec<u8>>, // Platform key used for proxy re-encryption
                  // Integer mod Z_q
    pub k_reg: Option<Vec<u8>>, // Registration key also used for proxy re-encyrption
               // Group element in G_2
    pub sk_p: Vec<([u8; 32], Rsa<Public>)> // Vector of Moderator keys accessible to the Platform
}

// Platform Implementation
impl Platform {
    pub fn new() -> Platform {
        Platform {
            k_p: None,
            k_reg: None,
            sk_p: Vec::<([u8; 32], Rsa<Public>)>::new()
        }
    }

    pub fn setup_platform(&mut self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        self.k_p = None;
        self.k_reg = None;

        (self.k_p.clone(), self.k_reg.clone())
    }

    pub fn process(_k_p: Option<Vec<u8>>, ks: &Vec<([u8; 32], Rsa<Public>)>, _c1: &Vec<u8>, c2: &Vec<u8>, ad: u32, ctx: &Vec<u8>) -> (Vec<u8>, (Vec<u8>, u32)) {
        let moderator_id: usize = ad.try_into().unwrap();
        let (mac_key_i, mod_pk_i) = &ks[moderator_id];
        let sigma_pt = mac_sign(&mac_key_i, &[&c2[..], &ctx[..]].concat());


        let keypair = PKey::from_rsa(mod_pk_i.clone()).unwrap();
        let mut encrypter = Encrypter::new(&keypair).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        let buffer_len = encrypter.encrypt_len(&sigma_pt).unwrap();
        
        let mut sigma = vec![0; buffer_len];

        let len = encrypter.encrypt(&sigma_pt, &mut sigma).unwrap();
        sigma.truncate(len);


        (sigma, (ctx.to_vec(), ad))
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

    pub fn ccae_enc(msg_key: Key<Aes256Gcm>, message: &str) -> (Vec<u8>, Vec<u8>) {
        let k_f: [u8; 32] = mac_keygen(); // franking key or r in H(m, r) for committment
        
        let c2 = com_commit(&k_f, message);

        let cipher = Aes256Gcm::new(&msg_key);
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let payload = bincode::serialize(&(message, k_f)).expect("");
        let c1_obj = cipher.encrypt(&nonce, payload.as_slice()).unwrap();
        let c1 = bincode::serialize::<(Vec<u8>, Vec<u8>)>(&(c1_obj, nonce.to_vec())).expect("");

        (c1, c2)
    }

    pub fn ccae_dec(msg_key: Key<Aes256Gcm>, c1: &Vec<u8>, c2: &Vec<u8>) -> (String, [u8; 32]) {
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

    pub fn send(msg_key: Key<Aes256Gcm>, message: &str, moderator_id: u32) -> (Vec<u8>, Vec<u8>, u32) {
        let (c1, c2) = Self::ccae_enc(msg_key, message);       

        (c1, c2, moderator_id)
    }
    
    pub fn read(msg_key: Key<Aes256Gcm>, _pks: &Vec<Rsa<Public>>, c1: &Vec<u8>, c2: &Vec<u8>, sigma: &Vec<u8>, st: &(Vec<u8>, u32)) -> (String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>)) {
        let (ctx, ad) = st;

        let (message, k_f) = Self::ccae_dec(msg_key, c1, c2);

        let report: ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>) = (k_f, c2.clone(), ctx.clone(), sigma.clone());


        (message, *ad, report)
    }
}
