use criterion::*;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use third_party_reporting::lib_basic as basic;

const CTX_LEN: usize = 100;
const LOG_SCALE: [usize; 8] = [10, 20, 40, 80, 160, 320, 640, 1280];

pub fn process(platform: &basic::Platform, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>) {
    let (c1, c2, ad) = &c1c2ad[0];
    let ctx = Alphanumeric.sample_string(&mut rand::thread_rng(), CTX_LEN);
    basic::Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, *ad, &(ctx.as_bytes().to_vec()));
}


pub fn bench_basic_process(c: &mut Criterion) {
    // Setup platform
    let mut platform = basic::test_basic_setup_platform();

    // One time setup to generate client needed for message sending
    let clients = basic::test_basic_init_clients(1);

    // Setup moderator to process reports under
    let (_moderators, _pks) = basic::test_basic_setup_mod(&mut platform, 1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(LOG_SCALE.len());
    for msg_size in LOG_SCALE.iter() {
        ms.push(basic::test_basic_init_messages(1, *msg_size));
    }

    // Send messages
    let mut c1c2ad: Vec<Vec<(Vec<u8>, Vec<u8>, u32)>> = Vec::with_capacity(LOG_SCALE.len());
    for (i, _msg_size) in LOG_SCALE.iter().enumerate() {
        c1c2ad.push(basic::test_basic_send(1, 1, &clients, &ms[i], false));
    }

    let mut group = c.benchmark_group("process(k_p, ks, c1, c2, ad, ctx)");
    for (i, msg_size) in LOG_SCALE.iter().enumerate() {
        group.bench_with_input(format!("Processed message of size {}", msg_size), msg_size, |b, &_msg_size| {
            b.iter(|| process(&platform, &c1c2ad[i]))
        });
    }
    
    group.finish();
}

criterion_group!(benches, bench_basic_process);
criterion_main!(benches);
