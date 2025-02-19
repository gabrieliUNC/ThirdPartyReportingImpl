use criterion::*;

use curve25519_dalek::ristretto::RistrettoPoint;
use aes_gcm::Nonce;
use generic_array::typenum::U12;
use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_common::*;

type Point = RistrettoPoint;
type Ciphertext = ((Point, Point), Vec<u8>, Nonce<U12>);


pub fn bench_basic_report(c: &mut Criterion) {
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
    let c1c2ad = basic::test_send_variable(&clients, &ms);

    // Process messages
    let sigma_st = basic::test_process_variable(&moderators, &c1c2ad, &platforms);

    // Read messages
    let mut rds: Vec<Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext))>> = Vec::new();
    // reports[i][j] = report on message j to moderator for platform i
    for i in 0..moderators.len() {
        let mut tmp: Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext))> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, _msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            let rd = basic::test_basic_read(1, &c1c2ad[i][j], &sigma_st[i][j], &clients, &pks[i], false);

            tmp.push(rd[0].clone());
        }
        rds.push(tmp);
    }
    
    let mut group = c.benchmark_group("basic.report()");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("basic.report() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                let (message, ad, rd) = &rds[i][j];
                b.iter(|| basic::Client::report_gen(&message, &rd))
            });
        }
    }
    
    group.finish();
}

criterion_group!(benches, bench_basic_report);
criterion_main!(benches);
