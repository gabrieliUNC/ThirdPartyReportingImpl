use criterion::*;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use third_party_reporting::lib_plain as plain;
use third_party_reporting::lib_common::*;



pub fn bench_plain_process(c: &mut Criterion) {
    // One time setup to generate client needed for message sending
    let clients = plain::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(plain::test_init_messages(1, *msg_size));
    }

    // Send messages
    let c1c2 = plain::test_send(&clients, &ms, false);

    // Setup Moderator
    let moderator = plain::Moderator::new();

    let mut group = c.benchmark_group("plain.process()");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(format!("plain.process() message of size {}", msg_size), msg_size, |b, &_msg_size| {
            let (c1, c2) = &c1c2[j];
            b.iter(|| plain::Moderator::mod_process(&moderator.k_m, &c2, &CTX_STR))
        });
    }
    
    group.finish();
}

criterion_group!(benches, bench_plain_process);
criterion_main!(benches);
