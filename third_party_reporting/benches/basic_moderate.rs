use criterion::*;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use third_party_reporting::lib_basic as basic;

const CTX_LEN: usize = 100;
const LOG_SCALE: [usize; 8] = [10, 20, 40, 80, 160, 320, 640, 1280];


pub fn bench_basic_moderate(c: &mut Criterion) {
    // Setup platform
    let mut platform = basic::test_basic_setup_platform();

    // One time setup to generate client needed for message sending
    let clients = basic::test_basic_init_clients(1);

    // Setup moderator to process reports under
    let (moderators, pks) = basic::test_basic_setup_mod(&mut platform, 1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(LOG_SCALE.len());
    for msg_size in LOG_SCALE.iter() {
        ms.push(basic::test_basic_init_messages(1, *msg_size));
    }

    // Send messages
    let mut c1c2ad: Vec<Vec<(Vec<u8>, Vec<u8>, u32)>> = Vec::with_capacity(LOG_SCALE.len());
    for (i, msg_size) in LOG_SCALE.iter().enumerate() {
        c1c2ad.push(basic::test_basic_send(1, 1, &clients, ms[i].clone()));
    }

    // Process messages
    let mut sigma_st: Vec<Vec<(Vec<u8>, (Vec<u8>, u32))>> = Vec::with_capacity(LOG_SCALE.len());
    for (i, msg_size) in LOG_SCALE.iter().enumerate() {
        sigma_st.push(basic::test_basic_process(1, *msg_size, &c1c2ad[i], &platform));
    }

    // Read messages
    let mut reports: Vec<([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::with_capacity(LOG_SCALE.len());
    for (i, msg_size) in LOG_SCALE.iter().enumerate() {
        let report = basic::test_basic_read(1, &c1c2ad[i], &sigma_st[i], &clients, &pks);
        reports.push(report[0].2.clone());
    }

    let mut group = c.benchmark_group("moderate(k, pks, c1, c2, sigma, st)");
    for (i, msg_size) in LOG_SCALE.iter().enumerate() {
        group.bench_with_input(format!("Moderated message of size {}", msg_size), msg_size, |b, &msg_size| {
            b.iter(|| basic::Moderator::moderate(moderators[0].keypair.clone(), moderators[0].sk_p.clone(), &ms[i][0], reports[i].clone()))
        });
    }
    
    group.finish();
}

criterion_group!(benches, bench_basic_moderate);
criterion_main!(benches);
