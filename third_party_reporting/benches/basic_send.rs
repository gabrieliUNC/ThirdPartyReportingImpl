use criterion::*;
use third_party_reporting::lib_basic as basic;

const MAX_CLIENTS: usize = 1280;
const LOG_SCALE: [usize; 8] = [10, 20, 40, 80, 160, 320, 640, 1280];

pub fn send(num_clients: usize, clients: &Vec<basic::Client>, ms: &Vec<String>) {
    for i in 0..num_clients {
        basic::Client::send(clients[i].msg_key, &ms[i], i.try_into().unwrap());
    }
}


pub fn bench_basic_send(c: &mut Criterion) {
    // One time setup to generate clients needed for message sending
    let clients = basic::test_basic_init_clients(MAX_CLIENTS);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(LOG_SCALE.len());
    for msg_size in LOG_SCALE.iter() {
        ms.push(basic::test_basic_init_messages(MAX_CLIENTS, *msg_size));
    }

    let mut group = c.benchmark_group("send(k, m, pk_i)");
    for num_clients in LOG_SCALE.iter() {
        for (i, msg_size) in LOG_SCALE.iter().enumerate() {
            group.bench_with_input(format!("Sent {} messages of size {}", num_clients, msg_size), num_clients, |b, &num_clients| {
                b.iter(|| send(num_clients, &clients, &ms[i]))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_basic_send);
criterion_main!(benches);
