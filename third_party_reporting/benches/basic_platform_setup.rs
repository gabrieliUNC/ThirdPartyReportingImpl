use criterion::{criterion_group, criterion_main, Criterion};
use third_party_reporting::lib_basic as basic;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("SetupPlatform(1^lambda)", |b| b.iter(|| basic::test_basic_setup_platform()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
