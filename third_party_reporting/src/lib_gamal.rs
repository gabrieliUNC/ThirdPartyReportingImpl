extern crate rand_core;
use rand_core::OsRng;
use sha2::{Sha256, Digest};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{RistrettoPoint, RistrettoBasepointTable, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use rand::rngs;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce
};

use generic_array::typenum::U12;
type Point = RistrettoPoint;


// El Gamal Scheme
type Ciphertext = (Point, Point);

pub(crate) const G: &RistrettoBasepointTable = &constants::RISTRETTO_BASEPOINT_TABLE;

pub(crate) fn pzip(p: Point) -> [u8; 32] {
    p.compress().to_bytes()
}

pub(crate) fn puzip(p: [u8; 32]) -> Point {
    CompressedRistretto::from_slice(&p).decompress().unwrap()
}

pub(crate) fn elgamal_keygen() -> (Scalar, Point) {
    let x: Scalar = Scalar::random(&mut OsRng);
    let h: Point = &x * G;
    (x, h)
}

pub(crate) fn elgamal_enc(pk: Point, m: Point) -> Ciphertext {
    let r = Scalar::random(&mut OsRng);
    let c1 = &r*G;
    let c2 = &r*pk + m;

    (c1, c2)
}

// Takes as parameters:
//      sk: a compressed Scalar
//      ct:  a compressed (Point, Point) ciphertext
// Returns the decrypted chosen mask
pub(crate) fn elgamal_dec(sk: Scalar, ct: Ciphertext) -> Point {
    ct.1 + (Scalar::zero() - sk) * ct.0
}

pub(crate) fn encrypt(pk: Point, m: Vec<u8>) -> (Ciphertext, Vec<u8>, Nonce<U12>) {
    // Choose random point p to encrypt with ElGamal. H(p) is the symmetric key
    // (we model H as a random oracle)
    let p = Point::random(&mut OsRng);
    let ct = elgamal_enc(pk, p);

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

pub(crate) fn decrypt(sk: Scalar, ct: (Ciphertext, Vec<u8>), nonce: Nonce<U12>) -> Vec<u8> {
    let p = elgamal_dec(sk, ct.0);

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, pzip(p));
    let k = hasher.finalize();

    let cipher = Aes256Gcm::new(&k);
    let pt = cipher.decrypt(&nonce, ct.1.as_ref()).ok();

    let m: Vec<u8> = pt.unwrap();

    m
}
