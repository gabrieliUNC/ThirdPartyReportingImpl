use criterion::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use aes_gcm::Nonce;
use generic_array::typenum::U12;
use third_party_reporting::lib_mod_priv as mod_priv;

type Point = RistrettoPoint;
type PublicKey = (Point, Point, Scalar);
type Ciphertext = ((Point, Point), Vec<u8>, Nonce<U12>);
const CTX_LEN: usize = 100;
const MSG_SIZE_SCALE: [usize; 8] = [8, 16, 32, 64, 128, 256, 512, 1024];
const MOD_SCALE: [usize; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

pub fn read(clients: &Vec<mod_priv::Client>, c1c2ad: &Vec<(Vec<u8>, Vec<u8>, Point)>, pks: &Vec<PublicKey>, sigma_st: &Vec<(Ciphertext, (Vec<u8>, Point))>) {
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
    let mut c1c2ad: Vec<Vec<Vec<(Vec<u8>, Vec<u8>, Point)>>> = Vec::new();
    // c1c2ad[i][j] = Encryption of message j to moderator i
    for i in 0..moderators.len() {
        let mut tmp: Vec<Vec<(Vec<u8>, Vec<u8>, Point)>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(mod_priv::test_send(1, &moderators[i], &clients, &ms[j], false));
        }
        c1c2ad.push(tmp);
    }

    // Process messages
    let mut sigma_st: Vec<Vec<Vec<(Ciphertext, (Vec<u8>, Point))>>> = Vec::new();
    // sigma_st[i][j] = encrypted signature on message commitmment j to moderator i
    for i in 0..moderators.len() {
        let mut tmp: Vec<Vec<(Ciphertext, (Vec<u8>, Point))>> = Vec::with_capacity(MSG_SIZE_SCALE.len());
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            tmp.push(mod_priv::test_process(1, *msg_size, &c1c2ad[i][j], &platforms[i], false));
        }
        sigma_st.push(tmp);
    }

    let mut group = c.benchmark_group("mod_priv.read(k, pks, c1, c2, sigma, st)");
    
    for (i, num_moderators) in MOD_SCALE.iter().enumerate() {
        for (j, msg_size) in MSG_SIZE_SCALE.iter().enumerate() {
            group.bench_with_input(format!("Read message of size {} with {} moderators", msg_size, num_moderators), msg_size, |b, &_msg_size| {
                b.iter(|| read(&clients, &c1c2ad[i][j], &pks[i], &sigma_st[i][j]))
            });
        }
    }
    
    group.finish();
}
criterion_group!(benches, bench_mod_priv_read);
criterion_main!(benches);
