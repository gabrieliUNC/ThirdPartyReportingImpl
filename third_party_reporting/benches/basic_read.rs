use criterion::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use aes_gcm::Nonce;
use generic_array::typenum::U12;
use third_party_reporting::lib_basic as basic;

type Point = RistrettoPoint;
type Ciphertext = ((Point, Point), Vec<u8>, Nonce<U12>);
const LOG_SCALE: [usize; 8] = [10, 20, 40, 80, 160, 320, 640, 1280];

pub fn read(clients: &Vec<basic::Client>, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, u32)>, pks: &Vec<Point>, sigma_st: &Vec<(Ciphertext, (Vec<u8>, u32))>) {
    let (c1, c2, _ad) = &c1c2ad[0];
    let (sigma, st) = &sigma_st[0];
    basic::Client::read(&clients[0].msg_key, &pks, &c1, &c2, &sigma, &st);
}


pub fn bench_basic_read(c: &mut Criterion) {
    // Setup platform
    let mut platform = basic::test_basic_setup_platform();

    // One time setup to generate client needed for message sending
    let clients = basic::test_basic_init_clients(1);

    // Setup moderator to process reports under
    let (_moderators, pks) = basic::test_basic_setup_mod(&mut platform, 1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(LOG_SCALE.len());
    for msg_size in LOG_SCALE.iter() {
        ms.push(basic::test_basic_init_messages(1, *msg_size));
    }

    // Send messages
    let mut c1c2ad: Vec<Vec<(Vec<u8>, Vec<u8>, u32)>> = Vec::with_capacity(LOG_SCALE.len());
    for (i, _msg_size) in LOG_SCALE.iter().enumerate() {
        c1c2ad.push(basic::test_basic_send(1, 1, &clients, &ms[i], false));
    }

    // Process messages
    let mut sigma_st: Vec<Vec<(Ciphertext, (Vec<u8>, u32))>> = Vec::with_capacity(LOG_SCALE.len());
    for (i, msg_size) in LOG_SCALE.iter().enumerate() {
        sigma_st.push(basic::test_basic_process(1, *msg_size, &c1c2ad[i], &platform, false));
    }

    let mut group = c.benchmark_group("read(k, pks, c1, c2, sigma, st)");
    for (i, msg_size) in LOG_SCALE.iter().enumerate() {
        group.bench_with_input(format!("Read message of size {}", msg_size), msg_size, |b, &_msg_size| {
            b.iter(|| read(&clients, &c1c2ad[i], &pks, &sigma_st[i]))
        });
    }
    
    group.finish();
}
criterion_group!(benches, bench_basic_read);
criterion_main!(benches);
