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
use rand_core::OsRng;

type PublicKey = (Point, Point, Scalar);
type Point = RistrettoPoint;
type Ciphertext = ((Point, Point), Vec<u8>, Nonce<U12>);
use generic_array::typenum::U12;


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
            pk_enc_1: keys.1,
            pk_enc_2: keys2.1,
            k1_2: keys2.0 * keys.0.invert() // sk2 / sk1
        }
    }

    pub fn moderate(sk_enc: &Scalar, sk_p: &[u8; 32], moderator_id: usize, message: &str, report: &([u8; 32], Vec<u8>, Vec<u8>, Ciphertext)) -> String {
        let (k_f, c2, ctx, ct) = report;
        let (el_gamal_ct, sigma, nonce) = ct;

        let sigma_pt = gamal::pre_dec(*sk_enc, (*el_gamal_ct, sigma.to_vec()), *nonce);
        let sigma_pt:Vec<Vec<u8>> = bincode::deserialize(&sigma_pt).unwrap();

        // Verify committment
        assert!(com_open(&c2, message, k_f));

        // Verify signature
        assert!(mac_verify(&sk_p, &[&c2[..], &ctx[..]].concat(), sigma_pt[moderator_id].clone()));

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

    pub fn setup_platform(&mut self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        self.k_p = None;
        self.k_reg = None;

        (self.k_p.clone(), self.k_reg.clone())
    }

    pub fn process(_k_p: &Option<Vec<u8>>, ks: &Vec<([u8; 32], Point)>, _c1: &Vec<u8>, c2: &Vec<u8>, ad: Point, ctx: &Vec<u8>) -> (Ciphertext, (Vec<u8>, Point)) {
        let mut sigma_pt: Vec<Vec<u8>> = Vec::with_capacity(ks.len());
        for i in 0..ks.len() {
            sigma_pt.push(mac_sign(&ks[i].0, &[&c2[..], &ctx[..]].concat()));
        }

        let pk = ad;
        let payload = bincode::serialize(&sigma_pt).expect("");
        let ct = gamal::pre_enc(pk, (*payload.as_slice()).to_vec());


        (ct, (ctx.to_vec(), pk))
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
        let k_r = Scalar::from_bytes_mod_order(k_r); // Right function?????

        // Verify committment
        assert!(com_open(&c2, message, &k_f));

        (message.to_string(), moderator_id, k_f, k_r)
    }

    pub fn send(msg_key: &Key<Aes256Gcm>, message: &str, moderator_id: u32, pk_i: PublicKey) -> (Vec<u8>, Vec<u8>, Point) {
        let (pk1, pk2, k1_2) = pk_i;
        let s: Scalar = Scalar::random(&mut OsRng);
        let pk = &s * pk1;
        let k_r = k1_2 * s.invert();

        let (c1, c2) = Self::ccae_enc(msg_key, message, moderator_id, k_r);       

        (c1, c2, pk)
    }
    
    pub fn read(msg_key: &Key<Aes256Gcm>, pks: &Vec<Point>, c1: &Vec<u8>, c2: &Vec<u8>, sigma: &Ciphertext, st: &(Vec<u8>, Point)) -> (String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext)) {
        let (ctx, pk) = st;
        let (message, moderator_id, k_f, k_r) = Self::ccae_dec(msg_key, c1, c2);

        let pk2 = pks[usize::try_from(moderator_id).unwrap()];

        // Ensure this message is reportable
        assert!((&k_r * pk) == pk2);
        
        let (ct, sym_ct, nonce) = sigma;
        let sigma_r = gamal::pre_re_enc(*ct, k_r);


        let report: ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext) = (k_f, c2.clone(), ctx.clone(), (sigma_r, sym_ct.to_vec(), *nonce));


        (message, moderator_id, report)
    }
}



pub fn test_proxy() {
    
    // Setup()
    let kp1 = gamal::elgamal_keygen();
    let kp2 = gamal::elgamal_keygen();

    let sk_1 = kp1.0; // x
    let pk_1 = kp1.1; // g^x

    let sk_2 = kp2.0; // y
    let pk_2 = kp2.1; // g^y

    let k1_2 = sk_2 * sk_1.invert(); // y / x
    
    assert!(&k1_2*pk_1 == pk_2);


    // Send()
    let s: Scalar = Scalar::random(&mut OsRng);
    let pk = &s * pk_1; // g^(x*s)
    let k_r = k1_2 * s.invert(); // y / (x * s)
    
    assert!((&k_r*pk) == pk_2); // g^((x*s*y)/(x*s)) == g^y

    // Enc()
    let pt: Vec<u8> = [1, 0, 0, 0].to_vec();
    let (ct, sym_ct, nonce) = gamal::pre_enc(pk, pt); 
    //let (c1, c2) = ct;  // f <- R 
                        // (pt * g^f, g^(x*s*f))

    // ReEnc()
   //let c2_r = &k_r * c2; // g^((x*s*f*y)/(x*s))
                          // (g^f, g^(f*y) )

    let ct = gamal::pre_re_enc(ct, k_r);
    // Dec() under pk2
    let m = gamal::pre_dec(sk_2, (ct, sym_ct), nonce);

    println!("{:?}", m);

}


pub fn test_setup_platform() -> Platform {
    let platform = Platform::new();

    platform
}


// SetupMod(pk_reg, 1^lambda)
pub fn test_setup_mod(platform: &mut Platform, num_moderators: usize) -> (Vec<Moderator>, Vec<Point>) {
    let mut moderators: Vec<Moderator> = Vec::with_capacity(num_moderators);
    let mut pks: Vec<Point> = Vec::with_capacity(num_moderators);

    for _i in 0..num_moderators {
        let moderator = Moderator::new(&platform.k_reg);
        platform.sk_p.push((moderator.sk_p.clone(), moderator.pk_enc_2.clone()));
        pks.push(moderator.pk_enc_2.clone());
        moderators.push(moderator);
    }


    (moderators, pks)
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
        let (c1, c2, ad) = Client::send(&clients[i].msg_key, &ms[i], mod_i.try_into().unwrap(), pki);
        
        if print {
            println!("Sent message: {}", &ms[i]);
        }
        c1c2ad.push((c1, c2, ad));
    }

    c1c2ad
}


// process(k_p, ks, c1, c2, ad, ctx)
pub fn test_process(num_clients: usize, msg_size: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>, platform: &Platform, print: bool) -> Vec<(Ciphertext, (Vec<u8>, Point))> {
    let mut sigma_st: Vec<(Ciphertext, (Vec<u8>, Point))> = Vec::with_capacity(num_clients);
    // Platform processes message
    for i in 0..num_clients {
        let (c1, c2, ad) = &c1c2ad[i];
        let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), msg_size);
        if print {
            println!("Adding context: {}", ctx);
        }
        let (sigma, st) = Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, *ad, &(ctx.as_bytes().to_vec()));

        sigma_st.push((sigma, st));
    }

    sigma_st
}


// read(k, pks, c1, c2, sigma, st)
pub fn test_read(num_clients: usize, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>, sigma_st: &Vec<(Ciphertext, (Vec<u8>, Point))>, clients: &Vec<Client>, pks: &Vec<Point>, print: bool) -> Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext))> {
    // Receive messages
    let mut reports: Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext))> = Vec::with_capacity(num_clients);
    // Receive message 0 from client 0 to be moderated by randomly selected moderator mod_i
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
pub fn test_moderate(num_clients: usize, reports: &Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext))>, moderators: &Vec<Moderator>, print: bool) {
    // Moderate messages
    for i in 0..num_clients {
        let (message, moderator_id, report) = &reports[i];
        let j = usize::try_from(*moderator_id).unwrap();
        let ctx = Moderator::moderate(&moderators[j].sk_enc, &moderators[j].sk_p, j, &message, &report);
        if print {
            println!("Moderated message successfully with context: {:?}", ctx);
        }
    }

}
