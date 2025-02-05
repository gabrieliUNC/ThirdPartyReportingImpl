use blst::*;
use blstrs as blstrs;

// Generate new Field element mod q
// from blst scalar
pub fn new_blstrs_scalar(sk: &[u8; 32]) -> blstrs::Scalar {
    let sk = blst::blst_scalar { b: *sk };
    let mut f = blst_fr::default();

    unsafe {
        blst_fr_from_scalar(&mut f, &sk);
    }

    blstrs::Scalar::from_u64s_le(&f.l).unwrap()
}

