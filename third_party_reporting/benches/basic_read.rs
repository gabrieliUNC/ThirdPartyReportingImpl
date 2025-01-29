use criterion::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use aes_gcm::Nonce;
use generic_array::typenum::U12;
use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_common::*;

type Point = RistrettoPoint;
type Ciphertext = ((Point, Point), Vec<u8>, Nonce<U12>);

pub fn read(clients: &Vec<basic::Client>, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>, pks: &Vec<Point>, sigma_st: &Vec<(Ciphertext, (Vec<u8>, u32))>) {
    let (c1, c2, _ad) = &c1c2ad[0];
    let (sigma, st) = &sigma_st[0];
    basic::Client::read(&clients[0].msg_key, &pks, &c1, &c2, &sigma, &st);
}


pub fn bench_basic_read(c: &mut Criterion) {
    // Setup platforms and moderators
    let (platforms, moderators, pks) = basic::test_setup();

    // One time setup to generate client needed for message sending
    let clients = basic::test_basic_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(basic::test_basic_init_messages(1, *msg_size));
    }

    // Send messages
    let mut c1c2ad = basic::test_send_variable(&clients, &ms);

    // Process messages
    let mut sigma_st = basic::test_process_variable(&moderators, &c1c2ad, &platforms);

    let mut group = c.benchmark_group("basic.read()");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("basic.read() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                b.iter(|| read(&clients, &c1c2ad[i][j], &pks[i], &sigma_st[i][j]))
            });
        }
    }
    
    group.finish();
}
criterion_group!(benches, bench_basic_read);
criterion_main!(benches);
