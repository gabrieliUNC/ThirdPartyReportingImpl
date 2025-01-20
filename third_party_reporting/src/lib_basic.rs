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
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::distributions::DistString;
use rand::Rng;

// Global constants
const RSA_MODULUS: u32 = 2048;



// Moderator Properties
pub struct Moderator {
    pub sk_p: [u8; 32], // Mac Key shared with the Platform
    pub keypair: PKey<Private>, // Moderator Encryption key pair
    pub pk_mod: Option<PKey<Public>> // Moderator public key
}

// Moderator Implementation 
impl Moderator {
    // SetupMod(pk_reg, 1^lambda)
    pub fn new(_pk_reg: &Option<Vec<u8>>) -> Moderator {
        let rsa = Rsa::generate(RSA_MODULUS).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        Moderator {
            sk_p: mac_keygen(),
            keypair: pkey,
            pk_mod: None
        }
    }

    // lazy init of public key
    // to provide users with public key on demand
    pub fn get_public_key(&mut self) -> Option<PKey<Public>> {
        if self.pk_mod.is_none() {
            self.pk_mod = Some(PKey::public_key_from_pem(&(self.keypair.public_key_to_pem().unwrap())).unwrap());
        }

        self.pk_mod.clone()
    }

    pub fn moderate(keypair: PKey<Private>, sk_p: [u8; 32], message: &str, report: ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>)) -> String {
        let (k_f, c2, ctx, sigma) = report;


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
    pub sk_p: Vec<([u8; 32], PKey<Public>)> // Vector of Moderator keys accessible to the Platform
}

// Platform Implementation
impl Platform {
    pub fn new() -> Platform {
        Platform {
            k_p: None,
            k_reg: None,
            sk_p: Vec::<([u8; 32], PKey<Public>)>::new()
        }
    }

    pub fn setup_platform(&mut self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        self.k_p = None;
        self.k_reg = None;

        (self.k_p.clone(), self.k_reg.clone())
    }

    pub fn process(_k_p: Option<Vec<u8>>, ks: &Vec<([u8; 32], PKey<Public>)>, _c1: &Vec<u8>, c2: &Vec<u8>, ad: u32, ctx: &Vec<u8>) -> (Vec<u8>, (Vec<u8>, u32)) {
        let moderator_id: usize = ad.try_into().unwrap();
        let (mac_key_i, mod_pk_i) = &ks[moderator_id];
        let sigma_pt = mac_sign(&mac_key_i, &[&c2[..], &ctx[..]].concat());


        let mut encrypter = Encrypter::new(&mod_pk_i).unwrap();
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
    
    pub fn read(msg_key: Key<Aes256Gcm>, _pks: &Vec<PKey<Public>>, c1: &Vec<u8>, c2: &Vec<u8>, sigma: &Vec<u8>, st: &(Vec<u8>, u32)) -> (String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>)) {
        let (ctx, ad) = st;

        let (message, k_f) = Self::ccae_dec(msg_key, c1, c2);

        let report: ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>) = (k_f, c2.clone(), ctx.clone(), sigma.clone());


        (message, *ad, report)
    }
}


// Basic scheme testing decomposition for benchmarking
// still have num_moderators as a variable despite 
// this having minimal effect on running time
// as clients choose 1 moderator and server
// encrypts under 1 moderator's pk

// SetupPlatform(1^lambda)
pub fn test_basic_setup_platform() -> Platform {
    let platform = Platform::new();

    platform
}

// SetupMod(pk_reg, 1^lambda)
pub fn test_basic_setup_mod(platform: &mut Platform, num_moderators: usize) -> (Vec<Moderator>, Vec<PKey<Public>>) {
    let mut moderators: Vec<Moderator> = Vec::with_capacity(num_moderators);
    let mut pks: Vec<PKey<Public>> = Vec::with_capacity(num_moderators);

    for _i in 0..num_moderators {
        let mut moderator = Moderator::new(&platform.k_reg);
        platform.sk_p.push((moderator.sk_p.clone(), moderator.get_public_key().expect("")));
        pks.push(moderator.get_public_key().expect(""));
        moderators.push(moderator);
    }


    (moderators, pks)
}

// Setup Clients
pub fn test_basic_init_clients(num_clients: usize, msg_size: usize) -> (Vec<Client>, Vec<String>) {
    let mut clients: Vec<Client> = Vec::with_capacity(num_clients);
    for _i in 0..num_clients {
        let client = Client::new();
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
pub fn test_basic_send(num_clients: usize, clients: &Vec<Client>, ms: Vec<String>) -> Vec<(Vec<u8>, Vec<u8>, u32)> {
    let mut c1c2ad: Vec<(Vec<u8>, Vec<u8>, u32)> = Vec::with_capacity(num_clients);
    // send message i to client i to be moderated by random mod
    let mut rng = thread_rng();
    for i in 0..num_clients {
        let mod_i = rng.gen_range(0..10);
        let (c1, c2, ad) = Client::send(clients[i].msg_key, &ms[i].clone(), mod_i);
        
        println!("Sent message: {}", &ms[i]);
        c1c2ad.push((c1, c2, ad));
    }

    c1c2ad
}

// process(k_p, ks, c1, c2, ad, ctx)
pub fn test_basic_process(num_clients: usize, msg_size: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>, platform: &Platform) -> Vec<(Vec<u8>, (Vec<u8>, u32))> {
    let mut sigma_st: Vec<(Vec<u8>, (Vec<u8>, u32))> = Vec::with_capacity(num_clients);
    // Platform processes message
    for i in 0..num_clients {
        let (c1, c2, ad) = &c1c2ad[i];
        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        println!("Adding context: {}", ctx);
        let (sigma, st) = Platform::process(platform.k_p.clone(), &platform.sk_p, &c1, &c2, *ad, &(ctx.as_bytes().to_vec()));

        sigma_st.push((sigma, st));
    }

    sigma_st
}

// read(k, pks, c1, c2, sigma, st)
pub fn test_basic_read(num_clients: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>, sigma_st: &Vec<(Vec<u8>, (Vec<u8>, u32))>, clients: &Vec<Client>, pks: &Vec<PKey<Public>>) -> Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>))> {
    // Receive messages
    let mut reports: Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>))> = Vec::with_capacity(num_clients);
    // Receive message 0 from client 0 to be moderated by randomly selected moderator mod_i
    for i in 0..num_clients {
        let (c1, c2, _ad) = &c1c2ad[i];
        let (sigma, st) = &sigma_st[i];
        let (message, ad, report) = Client::read(clients[i].msg_key, &pks, &c1, &c2, &sigma, &st);

        println!("Received message: {}", message);
        reports.push((message, ad, report));
    }

    reports
}

// moderate(sk_mod, sk_p, m, report)
pub fn test_basic_moderate(num_clients: usize, reports: &Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>))>, moderators: &Vec<Moderator>) {
    // Moderate messages
    for i in 0..num_clients {
        let (message, ad, report) = &reports[i];
        let ad = usize::try_from(*ad).unwrap();
        let ctx = Moderator::moderate(moderators[ad].keypair.clone(), moderators[ad].sk_p.clone(), &message, report.clone());
        println!("Moderated message successfully with context: {:?}", ctx);
    }

}
