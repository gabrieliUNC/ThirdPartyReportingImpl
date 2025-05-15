use criterion::*;

use third_party_reporting::lib_plain as plain;
use third_party_reporting::lib_common::*;


pub fn bench_plain_moderate(c: &mut Criterion) {
    // One time setup to generate client needed for message sending
    let clients = plain::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(plain::test_init_messages(1, *msg_size));
    }

    // Send messages
    let c1c2s = plain::test_send(&clients, &ms, false);

    // Process messages
    let moderator = plain::Moderator::new();
    let sigmas = plain::test_process(&moderator, &c1c2s);

    // Read messages
    let reports = plain::test_read(&clients, &c1c2s, &sigmas, false);

    let mut group = c.benchmark_group("plain.moderate()");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(format!("plain.moderate() message of size {}", msg_size), msg_size, |b, &_msg_size| {
            let (m, ctx, rd, sigma) = &reports[j].clone();
            b.iter(|| plain::Moderator::moderate(&moderator.k_m, &m, &ctx, rd.clone(), sigma.to_vec()))
        });
    }
    
    group.finish();
}

criterion_group!(benches, bench_plain_moderate);
criterion_main!(benches);
