use criterion::{criterion_group, criterion_main, Criterion};
use third_party_reporting::lib_constant_mod_priv as constant_mod_priv;

pub fn const_mod_priv_platform_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("constant-mod-priv.setup_platform()");
    group.bench_function("constant-mod-priv.setup_platform()", |b| b.iter(|| constant_mod_priv::test_setup_platform()));
    group.finish();
}

criterion_group!(benches, const_mod_priv_platform_setup);
criterion_main!(benches);
