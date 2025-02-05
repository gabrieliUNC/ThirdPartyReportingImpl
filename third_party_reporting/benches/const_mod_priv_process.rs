use criterion::*;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use third_party_reporting::lib_constant_mod_priv as constant_mod_priv;
use third_party_reporting::lib_common::*;
use blstrs as blstrs;
use curve25519_dalek::ristretto::RistrettoPoint;

type Point = RistrettoPoint;

pub fn process(platform: &constant_mod_priv::Platform, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, (Point, blstrs::G2Affine))>) {
    let (c1, c2, ad) = &c1c2ad[0];
    let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
    constant_mod_priv::Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, ad, &(ctx.as_bytes().to_vec()));
}


pub fn bench_const_mod_priv_process(c: &mut Criterion) {
    // Setup platforms and moderators
    let (platforms, moderators, pks) = constant_mod_priv::test_setup();

    // One time setup to generate client needed for message sending
    let clients = constant_mod_priv::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(constant_mod_priv::test_init_messages(1, *msg_size));
    }

    let mut c1c2ad = constant_mod_priv::test_send_variable(&moderators, &clients, &ms);

    let mut group = c.benchmark_group("const-mod-priv.process()");
    for (i, num_moderators) in  MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("const-mod-priv.process() with message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                b.iter(|| process(&platforms[i], &c1c2ad[i][j]))
            });
        }
    }
    
    group.finish();
}

criterion_group!(benches, bench_const_mod_priv_process);
criterion_main!(benches);
