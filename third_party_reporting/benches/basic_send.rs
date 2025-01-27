use criterion::*;
use third_party_reporting::lib_basic as basic;

const LOG_SCALE: [usize; 8] = [10, 20, 40, 80, 160, 320, 640, 1280];

pub fn bench_basic_send(c: &mut Criterion) {
    // One time setup to generate clients needed for message sending
    let clients = basic::test_basic_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(LOG_SCALE.len());
    for msg_size in LOG_SCALE.iter() {
        ms.push(basic::test_basic_init_messages(1, *msg_size));
    }

    let mut group = c.benchmark_group("basic.send(k, m, pk_i)");
    for (i, msg_size) in LOG_SCALE.iter().enumerate() {
        group.bench_with_input(format!("Sent message of size {}", msg_size), msg_size, |b, &_msg_size| {
            b.iter(|| basic::Client::send(&clients[0].msg_key, &ms[i][0], i.try_into().unwrap()))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_basic_send);
criterion_main!(benches);
