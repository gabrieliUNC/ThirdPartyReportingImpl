use criterion::*;
use third_party_reporting::lib_mod_priv as mod_priv;
const MOD_SCALE: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];


pub fn mod_priv_setup_mod(c: &mut Criterion) {
    // One time setup to generate platforms needed for mod setup
    let n: usize = usize::try_from(MOD_SCALE.len()).unwrap();
    let mut platforms: Vec<mod_priv::Platform> = Vec::with_capacity(n);

    for _i in 0..n {
        platforms.push(mod_priv::Platform::new());
    }

    let mut group = c.benchmark_group("mod_priv.SetupMod(pk_reg, 1^lambda)");
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        group.bench_with_input(format!("ModPriv.SetupMod() with {} moderators", num_moderators), num_moderators, |b, &num_moderators| {
            b.iter(|| mod_priv::test_setup_mod(&mut platforms[i], num_moderators.into()))
        });
    }
    group.finish();
}

criterion_group!(benches, mod_priv_setup_mod);
criterion_main!(benches);
