use criterion::*;
use third_party_reporting::lib_common::*;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use aes_gcm::Nonce;
use generic_array::typenum::U12;
use third_party_reporting::lib_mod_priv as mod_priv;


type ProcessState = (Ciphertext, Point, Vec<u8>);
type Point = CompressedRistretto;
type PublicKey = (Point, Point, Scalar);
type Ciphertext = (Point, Point);

pub fn read(clients: &Vec<mod_priv::Client>, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>, pks: &Vec<PublicKey>, sigma_st: &Vec<(Vec<u8>, ProcessState)>) {
    let (c1, c2, _ad) = &c1c2ad[0];
    let (sigma, st) = &sigma_st[0];
    mod_priv::Client::read(&clients[0].msg_key, &pks, &c1, &c2, &sigma, &st);
}


pub fn bench_mod_priv_read(c: &mut Criterion) {
    // Setup platforms and moderators
    let (platforms, moderators, pks) = mod_priv::test_setup();

    // One time setup to generate client needed for message sending
    let clients = mod_priv::test_init_clients(1);

    // One time setup to generate messages of various sizes
    let mut ms: Vec<Vec<String>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
    for msg_size in MSG_SIZE_SCALE.iter() {
        ms.push(mod_priv::test_init_messages(1, *msg_size));
    }

    // Send messages
    let c1c2ad = mod_priv::test_send_variable(&moderators, &clients, &ms);

    // Process messages
    let sigma_st = mod_priv::test_process_variable(&moderators, &c1c2ad, &platforms);

    let mut group = c.benchmark_group("mod-priv.read()");
    
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("mod-priv.read() message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                b.iter(|| read(&clients, &c1c2ad[i][j], &pks[i], &sigma_st[i][j]))
            });
        }
    }
    
    group.finish();
}
criterion_group!(benches, bench_mod_priv_read);
criterion_main!(benches);
