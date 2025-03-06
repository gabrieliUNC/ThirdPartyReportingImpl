use criterion::*;
use third_party_reporting::lib_gamal as gamal;
use third_party_reporting::lib_common::*;
use rand::thread_rng;
use rand::distributions::{Alphanumeric, DistString};

pub fn bench_gamal(c: &mut Criterion) {
    let mut keys = gamal::elgamal_keygen();
    let sigma = Alphanumeric.sample_string(&mut rand::thread_rng(), 256);

    c.bench_function("gamal-enc", |b| b.iter(|| gamal::encrypt(&keys.1, black_box(&sigma.as_bytes().to_vec()))));
}

criterion_group!(benches, bench_gamal);
criterion_main!(benches);
