use criterion::*;

use curve25519_dalek::ristretto::CompressedRistretto;
use aes_gcm::Nonce;
use generic_array::typenum::U12;
use third_party_reporting::lib_constant_mod_priv as constant_mod_priv;
use third_party_reporting::lib_common::*;
use blstrs as blstrs;

type Point = CompressedRistretto;
type Ciphertext = (Point, Point);

type Report = (Vec<u8>, [u8; 32], Vec<u8>, blstrs::Gt, Ciphertext);

pub fn bench_const_mod_priv_moderate(c: &mut Criterion) {
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

    // Read messages and generate reports
    let mut reports: Vec<Vec<(String, u32, Report)>> = Vec::new();
    // reports[i][j] = report doc for message j to moderator for platform i
    for i in 0..moderators.len() {
        let mut tmp: Vec<(String, u32, Report)> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, _msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            // read this message
            let rds = constant_mod_priv::test_read(1, &c1c2ad[i][j], &sigma_st[i][j], &clients, &pks[i], false);

            // Generate report for this message
            let reports = constant_mod_priv::test_report(1, &rds, false);
            tmp.push(reports[0].clone());
        }
        reports.push(tmp);
    }

    let mut group = c.benchmark_group("const-mod-priv.moderate()");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("const-mod-priv.moderate() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                let (_message, moderator_id, report) = &reports[i][j];
                let k = usize::try_from(*moderator_id).unwrap();
                b.iter(|| constant_mod_priv::Moderator::moderate(&moderators[i][k].sk_enc, &moderators[i][k].k, &moderators[i][k].sk_p, k, &ms[j][0], &report))
            });
        }
    }
    
    group.finish();
}

criterion_group!(benches, bench_const_mod_priv_moderate);
criterion_main!(benches);
