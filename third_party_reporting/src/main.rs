use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_mod_priv as mod_priv;
use clap::Parser;
use blst::*;
use blstrs as blstrs;
use blst::min_sig as G1;
use blst::min_pk as G2;
use rand_core::OsRng;
use rand::{RngCore, thread_rng};
use ff::Field;
use std::ptr;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Args {
    #[arg(long, default_value_t = false)]
    basic: bool,

    #[arg(long, default_value_t = false)]
    mod_priv: bool,

    #[arg(long, default_value_t = false)]
    constant_mod_priv: bool,

    #[arg(long, default_value_t = 10)]
    num_clients: usize,

    #[arg(long, default_value_t = 10)]
    num_moderators: usize,

    #[arg(long, default_value_t = 10)]
    msg_size: usize,

    #[arg(long, default_value_t = false)]
    test: bool
}

fn main() {
    let args = Args::parse();

    if args.test {
        test();
        return;
    }

    if args.basic {
        test_basic(args.num_clients, args.msg_size, args.num_moderators);
    }
    
    if args.mod_priv {
        test_priv(args.num_clients, args.msg_size, args.num_moderators);
    }

}

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


pub fn test() {
    // SetupPlatform()
    let k_p = BlsScalar::new();

    let k_p_inv = k_p.inverse();

    let k_reg = BlsP2::new(&k_p_inv);


    // SetupMod()
    let k = BlsScalar::new();
    let pk_proc = k_reg.multiply(k);


    // Process()
    let ctx = "asdasdfdas".as_bytes();
    let mut p1 = blst_p1::default();

    unsafe {
        blst_hash_to_g1(&mut p1, ctx.as_ptr(), ctx.len(), ptr::null(), 0, ptr::null(), 0);
    }
    
    let g1p1 = BlsP1::new_from_p1(p1).to_affine();
    let g2p2 = pk_proc.to_affine();

    let gt = blstrs::pairing(&g1p1, &g2p2);
}

pub fn test_constant_priv(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Moderator Privacy Scheme ====================");
    println!();
    println!();
    


}

// Method for running the moderator privacy scheme flow with variable number of clients, msg sizes
// and number of moderators
pub fn test_priv(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Moderator Privacy Scheme ====================");
    println!();
    println!();

    // Initialize Platform
    let mut platform = mod_priv::test_setup_platform();

    // Initialize Moderators
    let (moderators, pks) = mod_priv::test_setup_mod(&mut platform, num_moderators);

    // Initialize Clients
    let clients = mod_priv::test_init_clients(num_clients);

    // Prepare messages
    let ms = mod_priv::test_init_messages(num_clients, msg_size);

    // Send messages
    let c1c2ad = mod_priv::test_send(num_clients, &moderators, &clients, &ms, true);

    // Process messages
    let sigma_st = mod_priv::test_process(num_clients, msg_size, &c1c2ad, &platform, true);

    // Read messages
    let reports = mod_priv::test_read(num_clients, &c1c2ad, &sigma_st, &clients, &pks, true);

    // Moderate reports
    mod_priv::test_moderate(num_clients, &reports, &moderators, true);


    println!("======================== Finished Testing Moderator Privacy Scheme ====================");
    println!();
    println!();
}

// Method for running the whole basic scheme flow with variable number of clients / msgs sent, msg_size, and 
// number of moderators
pub fn test_basic(num_clients: usize, msg_size: usize, num_moderators: usize) {
    println!("======================== Started Testing Basic Scheme ====================");
    println!();
    println!();

    // Initialize platform
    let mut platform = basic::test_basic_setup_platform();

    // Initialize Moderators
    let (moderators, pks) = basic::test_basic_setup_mod(&mut platform, num_moderators);

    // Initialize Clients
    let clients = basic::test_basic_init_clients(num_clients);

    // Prepare messages
    let ms = basic::test_basic_init_messages(num_clients, msg_size);

    // Send messages
    let c1c2ad = basic::test_basic_send(num_clients, num_moderators, &clients, &ms, true);

    // Process messages
    let sigma_st = basic::test_basic_process(num_clients, msg_size, &c1c2ad, &platform, true);

    // Read messages and generate reports
    let reports = basic::test_basic_read(num_clients, &c1c2ad, &sigma_st, &clients, &pks, true);

    // Moderate reports
    basic::test_basic_moderate(num_clients, &reports, &moderators, true);


    println!("======================== Completed Testing Basic Scheme ====================");
    println!();
    println!();
}
