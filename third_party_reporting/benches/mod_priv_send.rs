use criterion::*;
use third_party_reporting::lib_mod_priv as mod_priv;
use third_party_reporting::lib_common::*;

pub fn mod_priv_send(c: &mut Criterion) {
    // One time setup to generate clients needed for message sending
    let clients = mod_priv::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let n: usize = usize::try_from(MSG_SIZE_SCALE.len()).unwrap();
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(n);
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(mod_priv::test_init_messages(1, *msg_size));
    }

    // One time setup of moderators
    let (_platforms, _mods, pks) = mod_priv::test_setup();

    let mut group = c.benchmark_group("mod-priv.send()");

    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("mod-priv.send() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                b.iter(|| mod_priv::Client::send(&clients[0].msg_key, &ms[j][0], i.try_into().unwrap(), &pks[i][0]))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, mod_priv_send);
criterion_main!(benches);
