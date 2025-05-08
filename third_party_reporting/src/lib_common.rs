use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512, Digest};
use rand::rngs::OsRng;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;
use blstrs as blstrs;
use blstrs::Scalar;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::rand_core::RngCore;
use ff::PrimeField;

const REPR_SHAVE_BITS: usize = 256 - blstrs::Scalar::NUM_BITS as usize;

pub const CTX_LEN: usize = 100;
pub const CTX_STR: &str = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean m";
pub const CTX: [u8; CTX_LEN] = *b"Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean m";
pub const MOD_SCALE: [usize; 11] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
pub const MSG_SIZE_SCALE: [usize; 1] = [100];

// Hash Sha256
pub fn hash(X: &Vec<u8>) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(X);
    let res = hasher.finalize();

    res.to_vec()
}

// Method for generating blstrs::Scalar from seed
pub fn new_blstrs_scalar(seed: [u8; 32]) -> blstrs::Scalar {
        // Generate randomness for blstrs::Scalar
        let mut rng = ChaCha20Rng::from_seed(seed);
        loop {
            let mut raw = [0u64; 4];
            for int in raw.iter_mut() {
                *int = rng.next_u64();
            }

            // Mask away the unused most-significant bits.
            raw[3] &= 0xffffffffffffffff >> REPR_SHAVE_BITS;

            if let Ok(Some(scalar)) = blstrs::Scalar::from_u64s_le(&raw).try_into() {
                return scalar;
            }
        }
}


// Committment Scheme
pub(crate) fn com_commit(r: &[u8], m: &str) -> Vec<u8> {
    let mut com = <HmacSha256 as Mac>::new_from_slice(r).expect("");
    com.update(m.as_bytes());
    let out = com.finalize();

    out.into_bytes().to_vec()
}

pub(crate) fn com_open(c: &Vec<u8>, m: &str, r: &[u8]) -> bool {
    let mut com = <HmacSha256 as Mac>::new_from_slice(r).expect("");
    com.update(m.as_bytes());
    let t = com.finalize();

    t.into_bytes().to_vec() == *c
}

// Mac Scheme
pub fn mac_keygen() -> [u8; 32] {
    let mut k: [u8; 32] = [0; 32];
    let mut rng = ChaCha20Rng::from_os_rng();
    rng.fill_bytes(&mut k);

    k
}

pub fn mac_64_keygen() -> [u8; 64] {
    let mut k: [u8; 64] = [0; 64];
    let mut rng = ChaCha20Rng::from_os_rng();
    rng.fill_bytes(&mut k);

    k
}

pub fn mac_sign(k: &[u8; 32], m: &Vec<u8>) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k).expect("");
    mac.update(&m);
    let sigma = mac.finalize().into_bytes().to_vec();

    sigma
}

pub fn mac_64_sign(k: &[u8; 64], m: &Vec<u8>) -> [u8; 64] {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(k).expect("");
    mac.update(&m);
    let sigma = mac.finalize().into_bytes();

    sigma.into()
}


pub(crate) fn mac_verify(k: &[u8; 32], m: &Vec<u8>, sigma: &Vec<u8>) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k).expect("");
    mac.update(&m);
    let t = mac.finalize().into_bytes().to_vec();

    let valid = *sigma == t;

    valid
}



// MAC prg
pub const MAC_PRG_CONST_1: &str = "MAC_PRG_CONSTANT_1";
pub const MAC_PRG_CONST_2: &str = "MAC_PRG_CONSTANT_2";
pub(crate) fn mac_prg(seed: &[u8; 32]) -> [u8; 64] {
    let s = mac_sign(seed, &MAC_PRG_CONST_1.as_bytes().to_vec());
    let r = mac_sign(seed, &MAC_PRG_CONST_2.as_bytes().to_vec());



    let mut ret: [u8; 64] = [0u8; 64];
    ret.copy_from_slice(&[&s[..], &r[..]].concat());

    ret
}
