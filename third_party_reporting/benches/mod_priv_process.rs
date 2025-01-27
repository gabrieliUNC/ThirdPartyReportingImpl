use criterion::*;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use third_party_reporting::lib_mod_priv as mod_priv;
use curve25519_dalek::ristretto::RistrettoPoint;

type Point = RistrettoPoint;
const CTX_LEN: usize = 100;
const MSG_SIZE_SCALE: [usize; 8] = [8, 16, 32, 64, 128, 256, 512, 1024];
const MOD_SCALE: [usize; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

pub fn process(platform: &mod_priv::Platform, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>) {
    let (c1, c2, ad) = &c1c2ad[0];
    let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
    mod_priv::Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, *ad, &(ctx.as_bytes().to_vec()));
}


pub fn bench_mod_priv_process(c: &mut Criterion) {
    // Setup platforms and moderators
    let (platforms, moderators, pks) = mod_priv::test_setup();

    // One time setup to generate client needed for message sending
    let clients = mod_priv::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(mod_priv::test_init_messages(1, *msg_size));
    }


    // Send messages
    let mut c1c2ad: Vec<Vec<Vec<(Vec<u8>, Vec<u8>, Point)>>> = Vec::new();
    // c1c2ad[i][j] = Encryption of message j to moderator i
    for i in 0..moderators.len() {
        let mut tmp: Vec<Vec<(Vec<u8>, Vec<u8>, Point)>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(mod_priv::test_send(1, &moderators[i], &clients, &ms[j], false));
        }
        c1c2ad.push(tmp);
    }


    let mut group = c.benchmark_group("mod_priv.process(k_p, ks, c1, c2, ad, ctx)");
    for (i, num_moderators) in  MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("Processed message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                b.iter(|| process(&platforms[i], &c1c2ad[i][j]))
            });
        }
    }
    
    group.finish();
}

criterion_group!(benches, bench_mod_priv_process);
criterion_main!(benches);
