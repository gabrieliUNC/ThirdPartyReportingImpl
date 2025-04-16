use criterion::*;
use third_party_reporting::lib_plain as plain;
use third_party_reporting::lib_common::*;

pub fn bench_plain_send(c: &mut Criterion) {
    // One time setup to generate clients needed for message sending
    let clients = plain::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(plain::test_init_messages(1, *msg_size));
    }

    let mut group = c.benchmark_group("plain.send()");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(format!("plain.send() message of size {}", msg_size), msg_size, |b, &_msg_size| {
            b.iter(|| plain::Client::send(&ms[j][0], clients[0].k_r))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_plain_send);
criterion_main!(benches);
