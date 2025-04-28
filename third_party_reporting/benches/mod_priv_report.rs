use criterion::*;

use curve25519_dalek::ristretto::CompressedRistretto;
use aes_gcm::Nonce;
use generic_array::typenum::U12;
use third_party_reporting::lib_mod_priv as mod_priv;
use third_party_reporting::lib_common::*;
use curve25519_dalek::scalar::Scalar;

type Point = CompressedRistretto;
type Ciphertext = (Point, Point);


type ReportDoc = ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>, Scalar, Ciphertext);

pub fn bench_mod_priv_report(c: &mut Criterion) {
    // Setup platforms and moderators
    let (platforms, moderators, pks) = mod_priv::test_setup();

    // One time setup to generate client needed for message sending
    let clients = mod_priv::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(mod_priv::test_init_messages(1, *msg_size));
    }


    // Send messages
    let c1c2ad = mod_priv::test_send_variable(&moderators, &clients, &ms);

    // Process messages
    let sigma_st = mod_priv::test_process_variable(&moderators, &c1c2ad, &platforms);

    // Read messages
    let mut rds: Vec<Vec<(String, u32, ReportDoc)>> = Vec::new();
    // rds[i][j] = report on message j to moderator for platform i
    for i in 0..moderators.len() {
        let mut tmp: Vec<(String, u32, ReportDoc)> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, _msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            let rd = mod_priv::test_read(1, &c1c2ad[i][j], &sigma_st[i][j], &clients, &pks[i], false);

            tmp.push(rd[0].clone());
        }
        rds.push(tmp);
    }

    let mut group = c.benchmark_group("mod-priv.report()");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("mod-priv.report() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                let (message, moderator_id, rd) = &rds[i][j];
                b.iter(|| mod_priv::Client::report_gen(&message, &rd))
            });
        }
    }
    
    group.finish();
}

criterion_group!(benches, bench_mod_priv_report);
criterion_main!(benches);
