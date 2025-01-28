use criterion::*;
use third_party_reporting::lib_mod_priv as mod_priv;
use third_party_reporting::lib_common::*;


pub fn mod_priv_setup_mod(c: &mut Criterion) {
    // One time setup to generate platforms needed for mod setup
    let n: usize = usize::try_from(MOD_SCALE.len()).unwrap();
    let mut platforms: Vec<mod_priv::Platform> = Vec::with_capacity(n);

    for _i in 0..n {
        platforms.push(mod_priv::Platform::new());
    }

    let mut group = c.benchmark_group("mod-priv.setup_mod()");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        group.bench_with_input(format!("mod-priv.setup_mod() with {} moderators", num_moderators), num_moderators, |b, &num_moderators| {
            b.iter(|| mod_priv::test_setup_mod(&mut platforms[i], num_moderators.into()))
        });
    }
    group.finish();
}

criterion_group!(benches, mod_priv_setup_mod);
criterion_main!(benches);
