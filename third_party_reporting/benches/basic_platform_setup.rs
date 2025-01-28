use criterion::{criterion_group, criterion_main, Criterion};
use third_party_reporting::lib_basic as basic;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("basic.setup_platform()");
    group.bench_function("basic.setup_platform()", |b| b.iter(|| basic::test_basic_setup_platform()));
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
