use criterion::*;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use aes_gcm::Nonce;
use generic_array::typenum::U12;
use third_party_reporting::lib_constant_mod_priv as constant_mod_priv;
use third_party_reporting::lib_common::*;
use blstrs as blstrs;

type Point = CompressedRistretto;
type Ciphertext = (Point, Point);

type Report_Doc = (Vec<u8>, [u8; 32], Vec<u8>, constant_mod_priv::G1Compressed, constant_mod_priv::G2Compressed, Scalar, Ciphertext);

pub fn bench_const_mod_priv_report(c: &mut Criterion) {
    // Setup platforms and moderators
    let (platforms, moderators, pks) = constant_mod_priv::test_setup();

    // One time setup to generate client needed for message sending
    let clients = constant_mod_priv::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(constant_mod_priv::test_init_messages(1, *msg_size));
    }


    // Send messages
    let c1c2ad = constant_mod_priv::test_send_variable(&moderators, &clients, &ms);

    // Process messages
    let sigma_st = constant_mod_priv::test_process_variable(&moderators, &c1c2ad, &platforms);

    // Read messages
    let mut report_docs: Vec<Vec<(String, u32, Report_Doc)>> = Vec::new();
    // report_docs[i][j] = report doc for message j to moderator for platform i
    for i in 0..moderators.len() {
        let mut tmp: Vec<(String, u32, Report_Doc)> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, _msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            // read this message
            let rds = constant_mod_priv::test_read(1, &c1c2ad[i][j], &sigma_st[i][j], &clients, &pks[i], false);

            tmp.push(rds[0].clone());
        }
        report_docs.push(tmp);
    }

    let mut group = c.benchmark_group("const-mod-priv.report()");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("const-mod-priv.report() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                let (message, _moderator_id, rd) = &report_docs[i][j];
                b.iter(|| constant_mod_priv::Client::report_gen(&message, &rd))
            });
        }
    }
    
    group.finish();
}

criterion_group!{
    name = benches;
    config = Criterion::default().significance_level(0.01).sample_size(50000);
    targets = bench_const_mod_priv_report
}
criterion_main!(benches);
