use criterion::*;
use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_common::*;

pub fn bench_basic_send(c: &mut Criterion) {
    // One time setup to generate clients needed for message sending
    let clients = basic::test_basic_init_clients(1);

    // Generate platforms and mods as in MOD_SCALE
    let (_platforms, _moderators, _pks) = basic::test_setup();

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(basic::test_basic_init_messages(1, *msg_size));
    }

    let mut group = c.benchmark_group("basic.send()");
    for (_i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("basic.send() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                b.iter(|| basic::Client::send(&clients[0].msg_key, &ms[j][0], j.try_into().unwrap()))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_basic_send);
criterion_main!(benches);
