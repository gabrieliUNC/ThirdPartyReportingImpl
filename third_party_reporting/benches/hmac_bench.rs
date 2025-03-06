use criterion::*;
use third_party_reporting::lib_common::*;
use rand::thread_rng;
use rand::distributions::{Alphanumeric, DistString};

pub fn bench_hmac(c: &mut Criterion) {
    let mut k = mac_keygen();
    let msg = Alphanumeric.sample_string(&mut rand::thread_rng(), 100);

    c.bench_function("hmac-sign", |b| b.iter(|| mac_sign(&k, black_box(&msg.as_bytes().to_vec()))));
}

criterion_group!(benches, bench_hmac);
criterion_main!(benches);
