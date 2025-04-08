use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce
};
use std::mem;

type Ciphertext = (Point, Point);
use generic_array::typenum::U12;
type Point = RistrettoPoint;


pub fn size_of_el_gamal_ct(ct: (Ciphertext, Vec<u8>, Nonce<U12>)) -> usize {
    let ((u, v), sym_ct, nonce) = ct;
    let mut cost: usize = mem::size_of_val(&u.compress()) + mem::size_of_val(&v.compress()) + mem::size_of_val(&*sym_ct) + mem::size_of_val(&*nonce);
    
    cost
}

// Proxy Re-Encryption El Gamal Scheme
pub(crate) fn pre_elgamal_enc(pk: &Point, m: &Point) -> Ciphertext {
    let r = Scalar::random(&mut OsRng);

    let c1 = RistrettoPoint::mul_base(&r) + m;
    let c2 = &r * pk;

    (c1, c2) // (g^(r) * m, g^(x*r)
}

pub(crate) fn pre_enc(pk: &Point, m: &Vec<u8>) -> (Ciphertext, Vec<u8>, Nonce<U12>) {
    // Choose random point p to encrypt with ElGamal. H(p) is the symmetric key
    // (we model H as a random oracle)
    let p = Point::random(&mut OsRng);
    let ct = pre_elgamal_enc(pk, &p);

    let pt = m;

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, pzip(p));
    let k = hasher.finalize();

    let cipher = Aes256Gcm::new(&k);
    let nonce = Aes256Gcm::generate_nonce(&mut rngs::OsRng);
    let sym_ct = cipher.encrypt(&nonce, pt.as_slice());

    let sym_ct = match sym_ct {
        Ok(ct) => ct,
        Err(_) => panic!("Symmetric encryption failed")
    };


    (ct, sym_ct, nonce)
}

pub(crate) fn pre_re_enc(ct: &Ciphertext, rk: &Scalar) -> Ciphertext {
    (ct.0, *&rk * ct.1) // (m * g^r, g^((x*r*s) * y * 1/(x*s)))
}

pub(crate) fn pre_elgamal_dec(sk: &Scalar, ct: &Ciphertext) -> Point {
    ct.0 - (ct.1 * sk.invert()) // g^r * m / g^((y*r)*(1/y))
}


pub(crate) fn pre_dec(sk: &Scalar, ct: &(Ciphertext, Vec<u8>), nonce: &Nonce<U12>) -> Vec<u8> {
    let p = pre_elgamal_dec(sk, &ct.0);

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, pzip(p));
    let k = hasher.finalize();

    let cipher = Aes256Gcm::new(&k);
    let pt = cipher.decrypt(&nonce, ct.1.as_ref()).ok();

    let m: Vec<u8> = pt.unwrap();

    m
}

// El Gamal Scheme


pub(crate) fn pzip(p: Point) -> [u8; 32] {
    p.compress().to_bytes()
}

pub fn elgamal_keygen() -> (Scalar, Point) {
    let x: Scalar = Scalar::random(&mut OsRng);
    let h: Point = RistrettoPoint::mul_base(&x);
    (x, h)
}

pub fn elgamal_enc(pk: &Point, m: &Point) -> Ciphertext {
    let r = Scalar::random(&mut OsRng);
    let c1 = RistrettoPoint::mul_base(&r);
    let c2 = &r*pk + m;

    (c1, c2)
}

// Takes as parameters:
//      sk: a compressed Scalar
//      ct:  a compressed (Point, Point) ciphertext
// Returns the decrypted chosen mask
pub(crate) fn elgamal_dec(sk: &Scalar, ct: &Ciphertext) -> Point {
    ct.1 + (Scalar::ZERO - sk) * ct.0 // m * g^(x*r) / g^(r/x)
}

pub fn encrypt(pk: &Point, m: &Vec<u8>) -> (Ciphertext, Vec<u8>, Nonce<U12>) {
    // Choose random point p to encrypt with ElGamal. H(p) is the symmetric key
    // (we model H as a random oracle)
    let p = Point::random(&mut OsRng);
    let ct = elgamal_enc(pk, &p);

    let pt = m;

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, pzip(p));
    let k = hasher.finalize();

    let cipher = Aes256Gcm::new(&k);
    let nonce = Aes256Gcm::generate_nonce(&mut rngs::OsRng);
    let sym_ct = cipher.encrypt(&nonce, pt.as_slice());

    let sym_ct = match sym_ct {
        Ok(ct) => ct,
        Err(_) => panic!("Symmetric encryption failed")
    };

    (ct, sym_ct, nonce)
}

pub(crate) fn decrypt(sk: &Scalar, ct: &(Ciphertext, Vec<u8>), nonce: &Nonce<U12>) -> Vec<u8> {
    let p = elgamal_dec(sk, &ct.0);

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, pzip(p));
    let k = hasher.finalize();

    let cipher = Aes256Gcm::new(&k);
    let pt = cipher.decrypt(&nonce, ct.1.as_ref()).ok();

    let m: Vec<u8> = pt.unwrap();

    m
}
