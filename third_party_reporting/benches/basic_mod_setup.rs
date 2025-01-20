use criterion::*;
use third_party_reporting::lib_basic as basic;

pub fn setup_mod(pk_reg: &Option<Vec<u8>>, num_moderators: usize) {
    for _i in 0..num_moderators {
        basic::Moderator::new(&pk_reg);
    }
}


pub fn bench_setup_mod(c: &mut Criterion) {
    // One time setup to generate platform needed for mod setup
    let platform = basic::test_basic_setup_platform();

    let mut group = c.benchmark_group("SetupMod(pk_reg, 1^lambda)");
    for num_moderators in [1, 10, 20, 50].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(num_moderators), num_moderators, |b, &num_moderators| {
            b.iter(|| setup_mod(&platform.k_reg, num_moderators))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_setup_mod);
criterion_main!(benches);
