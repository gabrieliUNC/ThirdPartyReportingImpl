use criterion::*;
use third_party_reporting::lib_basic as basic;

const MAX_CLIENTS: usize = 1000;
const MAX_MSG_SIZE: usize = 10;

pub fn send(num_clients: usize, clients: &Vec<basic::Client>, ms: &Vec<String>) {
    for i in 0..num_clients {
        basic::Client::send(clients[i].msg_key, &ms[i], i.try_into().unwrap());
    }
}


pub fn bench_basic_send(c: &mut Criterion) {
    // One time setup to generate clients needed for message sending
    let (clients, ms) = basic::test_basic_init_clients(MAX_CLIENTS, MAX_MSG_SIZE);

    let mut group = c.benchmark_group("send(k, m, pk_i)");
    for num_clients in [1, 10, 20, 50].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(num_clients), num_clients, |b, &num_clients| {
            b.iter(|| send(num_clients, &clients, &ms))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_basic_send);
criterion_main!(benches);
