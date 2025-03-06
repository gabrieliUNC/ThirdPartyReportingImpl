use criterion::*;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_common::*;

pub fn process(platform: &basic::Platform, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>) {
    let (c1, c2, ad) = &c1c2ad[0];
    basic::Platform::process(&platform.k_p, &platform.sk_p, &c1, &c2, *ad, &(CTX.to_vec()));
}


pub fn bench_basic_process(c: &mut Criterion) {
    // Setup platforms and moderators
    let (platforms, _moderators, _pks) = basic::test_setup();

    // One time setup to generate client needed for message sending
    let clients = basic::test_basic_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(basic::test_basic_init_messages(1, *msg_size));
    }

    // Send messages
    let c1c2ad = basic::test_send_variable(&clients, &ms);

    let mut group = c.benchmark_group("basic.process()");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("basic.process() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                b.iter(|| process(&platforms[i], &c1c2ad[i][j]))
            });
        }
    }
    
    group.finish();
}

criterion_group!(benches, bench_basic_process);
criterion_main!(benches);
