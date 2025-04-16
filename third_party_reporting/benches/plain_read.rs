use criterion::*;
use generic_array::typenum::U12;
use third_party_reporting::lib_plain as plain;
use third_party_reporting::lib_common::*;



pub fn bench_plain_read(c: &mut Criterion) {
    // One time setup to generate client needed for message sending
    let clients = plain::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(plain::test_init_messages(1, *msg_size));
    }

    // Send messages
    let c1c2s = plain::test_send(&clients, &ms);

    // Process messages
    let moderator = plain::Moderator::new();
    let sigmas = plain::test_process(&moderator, &c1c2s);

    let mut group = c.benchmark_group("plain.read()");
    for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
        group.bench_with_input(format!("plain.read() message of size {}", msg_size), msg_size, |b, &_msg_size| {
            let (c1, c2) = c1c2s[j].clone();
            let st = (c2, CTX_STR.to_string(), sigmas[j].clone());
            b.iter(|| plain::Client::read(clients[0].k_r, c1.clone(), st.clone()))
        });
    }
    
    group.finish();
}
criterion_group!(benches, bench_plain_read);
criterion_main!(benches);
