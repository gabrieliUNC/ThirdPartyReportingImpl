use blst::*;
use blstrs as blstrs;
use rand::thread_rng;
use std::ptr;
use blst::min_sig as G2;
use blst::min_pk as G1;
use rand::RngCore;

pub struct BlsP1 {
    pub pk: blst_p1
}

impl BlsP1 {
    pub fn new(sk: &BlsScalar) -> BlsP1 {
        let mut p1 = blst_p1::default();
        
        unsafe {
            blst_sk_to_pk_in_g1(&mut p1, &sk.sk);
        }

        BlsP1 { 
            pk: p1
        }
    }

    pub fn new_from_p1(p1: blst_p1) -> BlsP1 {
        BlsP1 {
            pk: p1
        }
    }
    
    pub fn multiply(&self, scalar: BlsScalar) -> BlsP1 {
        let mut ret = self.pk;
        unsafe {
            blst_p1_mult(&mut ret, &self.pk, scalar.to_bytes().as_ptr(), 255);
        }

        BlsP1 {
            pk: ret
        }
    }

    pub fn to_affine(&self) -> blstrs::G1Affine {
        let mut affine = blst_p1_affine::default();

        let mut compressed = [0u8; blstrs::G1Affine::compressed_size()];
        unsafe {
            blst_p1_to_affine(&mut affine, &self.pk);
            blst_p1_affine_compress(compressed.as_ptr().cast_mut(), &affine);
        }

        blstrs::G1Affine::from_compressed(&compressed).unwrap()
    }
}

pub struct BlsP2 {
    pub pk: blst_p2
}


impl BlsP2 {
    pub fn new(sk: &BlsScalar) -> BlsP2 {
        let mut p2 = blst_p2::default();
        
        unsafe {
            blst_sk_to_pk_in_g2(&mut p2, &sk.sk);
        }

        BlsP2 { 
            pk: p2
        }
    }
    
    pub fn multiply(&self, scalar: BlsScalar) -> BlsP2 {
        let mut ret = self.pk;
        unsafe {
            blst_p2_mult(&mut ret, &self.pk, scalar.to_bytes().as_ptr(), 255);
        }

        BlsP2 {
            pk: ret
        }
    }

    pub fn to_affine(&self) -> blstrs::G2Affine {
        let mut affine = blst_p2_affine::default();

        let mut compressed = [0u8; blstrs::G2Affine::compressed_size()];
        unsafe {
            blst_p2_to_affine(&mut affine, &self.pk);
            blst_p2_affine_compress(compressed.as_ptr().cast_mut(), &affine);
        }

        blstrs::G2Affine::from_compressed(&compressed).unwrap()
    }
}


pub struct BlsScalar {
    pub sk: blst_scalar
}

impl BlsScalar {
    pub fn new() -> BlsScalar {
        let mut s = blst_scalar::default();
        let mut rng = rand::thread_rng();

        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        unsafe {
            blst_scalar_from_le_bytes(&mut s, ikm.as_ptr(), ikm.len());
        }

        BlsScalar {
            sk: s
        }
    }

    pub fn new_from_scalar(s: blst_scalar) -> BlsScalar {
        BlsScalar {
            sk: s
        }
    }
    pub fn new_from_bytes(ikm: [u8; 32]) -> BlsScalar {
        let mut s = blst_scalar::default();
        unsafe {
            blst_scalar_from_le_bytes(&mut s, ikm.as_ptr(), ikm.len());
        }

        BlsScalar {
            sk: s
        }
    }
    
    pub fn inverse(&self) -> BlsScalar {
        let mut sk_inv = blst_scalar::default();
        
        unsafe {
            blst_sk_inverse(&mut sk_inv, &self.sk);
        }

        Self::new_from_scalar(sk_inv)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.sk.b.clone()
    }

    pub fn to_g2_sk(&self) -> G2::SecretKey {
        G2::SecretKey::from_bytes(&self.sk.b).expect("")
    }
    pub fn to_g1_sk(&self) -> G1::SecretKey {
        G1::SecretKey::from_bytes(&self.sk.b).expect("")
    }
}


pub fn g1_new_sk() -> G1::SecretKey {
    let mut ikm = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut ikm);

    G1::SecretKey::key_gen(&ikm, &[]).expect("") }


pub fn g2_new_sk() -> G2::SecretKey {
    let mut rng = thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    G2::SecretKey::key_gen(&ikm, &[]).unwrap()
}

pub fn new_blst_scalar() -> blst_scalar {
        let mut rng = rand::thread_rng();

        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        blst::blst_scalar { b : ikm }
}

pub fn scalar_inverse(scal: &[u8; 32]) -> blst_scalar {
    let mut sk_inv = blst_scalar::default();
    let sk: blst_scalar = blst::blst_scalar { b: *scal };

    unsafe {
        blst_sk_inverse(&mut sk_inv, &sk);
    }

    sk_inv
}

pub fn g1_inverse(scalar: &G1::SecretKey) -> G1::SecretKey {
    let mut sk_inv = scalar_inverse(&scalar.to_bytes());

    G1::SecretKey::from_bytes(&sk_inv.b).expect("")
}

pub fn g2_inverse(scalar: &G2::SecretKey) -> G2::SecretKey {
    println!("{:?}", scalar.to_bytes());
    let mut sk_inv = scalar_inverse(&scalar.to_bytes());

    println!("{:?}", sk_inv);
    G2::SecretKey::from_bytes(&sk_inv.b).expect("")
}

pub fn g1_sk_to_pk(g1sk: &G1::SecretKey) -> blstrs::G1Affine {
    let p1 = g1sk.sk_to_pk();
    
    blstrs::G1Affine::from_compressed(&p1.compress()).unwrap()
}


pub fn g2_sk_to_pk(g2sk: &G2::SecretKey) -> blstrs::G2Affine {
    let p2 = g2sk.sk_to_pk();
    
    blstrs::G2Affine::from_compressed(&p2.compress()).unwrap()
}

pub fn new_blstrs_scalar(sk: &[u8; 32]) -> blstrs::Scalar {
    let sk = blst::blst_scalar { b: *sk };
    let mut f = blst_fr::default();

    unsafe {
        blst_fr_from_scalar(&mut f, &sk);
    }

    blstrs::Scalar::from_u64s_le(&f.l).unwrap()
}

pub fn g2_mult(pk: &blstrs::G2Affine, sk: &blstrs::Scalar) -> blstrs::G2Affine {
    blstrs::G2Affine::from_compressed(&(pk * sk).to_compressed()).unwrap()
}


pub fn g2_mult_old(pk: &blstrs::G2Affine, sk: &[u8; 32]) -> blstrs::G2Affine {
    let scalar: blstrs::Scalar = new_blstrs_scalar(sk);
    blstrs::G2Affine::from_compressed(&(pk * scalar).to_compressed()).unwrap()
}

pub fn g1_mult(pk: &blstrs::G1Affine, sk: &[u8; 32]) -> blstrs::G1Affine {
    let scalar: blstrs::Scalar = new_blstrs_scalar(sk);
    blstrs::G1Affine::from_compressed(&(pk * scalar).to_compressed()).unwrap()
}

pub fn hash_to_g1(ctx: &Vec<u8>) -> blstrs::G1Affine {
    let mut p1 = blst_p1::default();

    unsafe {
        blst_hash_to_g1(&mut p1, ctx.as_ptr(), ctx.len(), ptr::null(), 0, ptr::null(), 0);
    }


    let mut affine = blst_p1_affine::default();
    let mut compressed = [0u8; blstrs::G1Affine::compressed_size()];
    unsafe {
        blst_p1_to_affine(&mut affine, &p1);
        blst_p1_affine_compress(compressed.as_ptr().cast_mut(), &affine);
    }

    blstrs::G1Affine::from_compressed(&compressed).unwrap()
}

pub fn g2_generator() -> blstrs::G2Affine {
    let mut g2 = blst_p2_affine::default();
    let mut compressed = [0u8; blstrs::G2Affine::compressed_size()];
    unsafe {
        g2 = *blst_p2_affine_generator();
        blst_p2_affine_compress(compressed.as_ptr().cast_mut(), &g2);
    }

    blstrs::G2Affine::from_compressed(&compressed).unwrap()
}
