use criterion::*;
use third_party_reporting::lib_basic as basic;
use third_party_reporting::lib_common::*;


pub fn bench_setup_mod(c: &mut Criterion) {
    // One time setup to generate platform needed for mod setup
    let mut platforms: Vec<basic::Platform> = Vec::new();
    for _i in 0..MOD_SCALE.len() {
        platforms.push(basic::Platform::new());
    }

    let mut group = c.benchmark_group("basic.setup_mod()");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        group.bench_with_input(format!("basic.setup_mod() with {} moderators", num_moderators), num_moderators, |b, &num_moderators| {
            b.iter(|| basic::test_basic_setup_mod(&mut platforms[i], num_moderators))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_setup_mod);
criterion_main!(benches);
