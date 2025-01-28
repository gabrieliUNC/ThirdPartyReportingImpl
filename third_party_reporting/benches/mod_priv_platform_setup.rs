use criterion::{criterion_group, criterion_main, Criterion};
use third_party_reporting::lib_mod_priv as mod_priv;

pub fn mod_priv_platform_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("mod_priv.setup_platform()");
    group.bench_function("mod-priv.setup_platform()", |b| b.iter(|| mod_priv::test_setup_platform()));
    group.finish();
}

criterion_group!(benches, mod_priv_platform_setup);
criterion_main!(benches);
