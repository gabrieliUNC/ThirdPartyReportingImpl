use criterion::*;

use curve25519_dalek::ristretto::RistrettoPoint;
use aes_gcm::Nonce;
use generic_array::typenum::U12;
use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_common::*;

type Point = RistrettoPoint;
type Ciphertext = ((Point, Point), Vec<u8>, Nonce<U12>);


pub fn bench_basic_moderate(c: &mut Criterion) {
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

    // Read messages
    let mut reports: Vec<Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext))>> = Vec::new();
    // reports[i][j] = report on message j to moderator for platform i
    for i in 0..moderators.len() {
        let mut tmp: Vec<(String, u32, ([u8; 32], Vec<u8>, Vec<u8>, Ciphertext))> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, _msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            let report = basic::test_basic_read(1, &c1c2ad[i][j], &sigma_st[i][j], &clients, &pks[i], false);
            tmp.push(report[0].clone());
        }
        reports.push(tmp);
    }
    
    let mut group = c.benchmark_group("basic.moderate()");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("basic.moderate() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                let (message, ad, report) = &reports[i][j];
                let k: usize = usize::try_from(*ad).unwrap();
                b.iter(|| basic::Moderator::moderate(&moderators[i][k].sk_enc, &moderators[i][k].sk_p, &ms[j][0], report))
            });
        }
    }
    
    group.finish();
}

criterion_group!(benches, bench_basic_moderate);
criterion_main!(benches);
