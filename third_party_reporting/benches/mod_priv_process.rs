use criterion::*;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use third_party_reporting::lib_mod_priv as mod_priv;
use third_party_reporting::lib_common::*;
use curve25519_dalek::ristretto::CompressedRistretto;

type Point = CompressedRistretto;

pub fn process(platform: &mod_priv::Platform, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>) {
    let (c1, c2, ad) = &c1c2ad[0];
    mod_priv::Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, ad, &(CTX.to_vec()));
}


pub fn bench_mod_priv_process(c: &mut Criterion) {
    // Setup platforms and moderators
    let (platforms, moderators, _pks) = mod_priv::test_setup();

    // One time setup to generate client needed for message sending
    let clients = mod_priv::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(mod_priv::test_init_messages(1, *msg_size));
    }

    let c1c2ad = mod_priv::test_send_variable(&moderators, &clients, &ms);

    let mut group = c.benchmark_group("mod-priv.process()");
    for (i, num_moderators) in  MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("mod-priv.process() with message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                b.iter(|| process(&platforms[i], &c1c2ad[i][j]))
            });
        }
    }
    
    group.finish();
}

criterion_group!(benches, bench_mod_priv_process);
criterion_main!(benches);
