use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::RngCore;
use rand::rngs::OsRng;
type HmacSha256 = Hmac<Sha256>;


pub const CTX_LEN: usize = 100;
pub const CTX_STR: &str = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean m";
pub const CTX: [u8; CTX_LEN] = *b"Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean m";
pub const MOD_SCALE: [usize; 1] = [64];
//[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048];
pub const MSG_SIZE_SCALE: [usize; 1] = [100];

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
    OsRng.fill_bytes(&mut k);

    k
}

pub fn mac_sign(k: &[u8; 32], m: &Vec<u8>) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k).expect("");
    mac.update(&m);
    let sigma = mac.finalize().into_bytes().to_vec();

    sigma
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
pub(crate) fn mac_prg(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let s = mac_sign(seed, &MAC_PRG_CONST_1.as_bytes().to_vec());
    let r = mac_sign(seed, &MAC_PRG_CONST_2.as_bytes().to_vec());
    (s, r)
}
