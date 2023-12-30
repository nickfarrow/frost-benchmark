use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{RngCore, SeedableRng};
use schnorr_fun::frost::{new_with_deterministic_nonces, Frost, FrostKey, KeyGen, SignSession};
use schnorr_fun::fun::poly;
use schnorr_fun::musig::NonceKeyPair;
use schnorr_fun::nonce::NonceGen;
use schnorr_fun::{frost, Signature};
use schnorr_fun::{
    fun::{
        digest::{generic_array::typenum::U32, Digest},
        marker::*,
        Scalar,
    },
    Message,
};

use sha2::Sha256;
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn generate_scalar_polys<R: RngCore>(
    threshold: usize,
    n_parties: usize,
    rng: &mut R,
) -> BTreeMap<Scalar<Public>, Vec<Scalar>> {
    (0..n_parties)
        .map(|i| {
            // println!("Creating poly", i);
            let index =
                Scalar::from_non_zero_u32(NonZeroU32::new((i + 1) as u32).expect("we added 1"))
                    .public();
            (index, poly::generate_scalar_poly(threshold, rng))
        })
        .collect::<BTreeMap<_, _>>()
}

pub fn generate_keygen_shares<H: Digest<OutputSize = U32> + Clone, NG: NonceGen>(
    frost: &Frost<H, NG>,
    keygen: &KeyGen,
    scalar_polys: &BTreeMap<Scalar<Public>, Vec<Scalar>>,
) -> BTreeMap<Scalar<Public>, (BTreeMap<frost::PartyIndex, Scalar<Secret, Zero>>, Signature)> {
    scalar_polys
        .clone()
        .into_iter()
        .map(|(party_index, sp)| {
            (
                party_index,
                frost.create_shares_and_pop(&keygen, &sp, Message::<Public>::empty()),
            )
        })
        .collect::<BTreeMap<_, _>>()
}

pub fn finish_keygen<H: Digest<OutputSize = U32> + Clone, NG: NonceGen>(
    frost: &Frost<H, NG>,
    keygen: &KeyGen,
    received_shares: BTreeMap<
        Scalar<Public>,
        BTreeMap<Scalar<Public>, (Scalar<Secret, Zero>, Signature)>,
    >,
) -> (FrostKey<Normal>, Vec<(Scalar<Public>, Scalar)>) {
    let mut frost_key = None;

    let secret_shares = received_shares
        .into_iter()
        .map(|(party_index, received_shares)| {
            // println!("Finishing keygen", party_index);
            let (secret_share, _frost_key) = frost
                .finish_keygen(
                    keygen.clone(),
                    party_index,
                    received_shares,
                    Message::<Public>::empty(),
                )
                .unwrap();

            frost_key = Some(_frost_key);
            (party_index, secret_share)
        })
        .collect();

    (frost_key.unwrap(), secret_shares)
}

pub fn sign<H: Digest<OutputSize = U32> + Clone, NG: NonceGen>(
    frost: &Frost<H, NG>,
    frost_key: &FrostKey<EvenY>,
    signing_session: &SignSession,
    secret_shares: &BTreeMap<Scalar<Public>, Scalar>,
    secret_nonces: &BTreeMap<Scalar<Public, NonZero>, NonceKeyPair>,
) -> Vec<Scalar<Public, Zero>> {
    let mut signatures = vec![];
    for (signer_index, secret_share) in secret_shares {
        let sig = frost.sign(
            &frost_key,
            &signing_session,
            signer_index.clone(),
            &secret_share,
            secret_nonces.get(&signer_index).unwrap().clone(),
        );

        assert!(frost.verify_signature_share(
            &frost_key,
            &signing_session,
            signer_index.clone(),
            sig
        ));
        signatures.push(sig);
    }
    signatures
}

fn frost_benchmark(c: &mut Criterion) {
    let seed: u64 = 42;
    let mut rng = StdRng::seed_from_u64(seed);

    let mut benchmark_thresholds = vec![];
    for n_parties in [1, 2, 4, 7, 12, 21, 35, 59, 100] {
        benchmark_thresholds.push((n_parties, n_parties));
    }

    let mut group = c.benchmark_group("frost");
    group.sample_size(20);

    // let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    // group.plot_config(plot_config);

    for input in benchmark_thresholds.into_iter() {
        let (threshold, n_parties) = input;
        group.throughput(Throughput::Elements(n_parties as u64));

        let frost = new_with_deterministic_nonces::<Sha256>();

        // KEYGEN
        let (frost_key, secret_shares) = {
            let scalar_polys = generate_scalar_polys(threshold, n_parties, &mut rng);
            group.bench_with_input(
                BenchmarkId::new("generate_scalar_polys", input.0),
                &input,
                |b, (threshold, _)| {
                    b.iter(|| generate_scalar_polys(*threshold, n_parties, &mut rng))
                },
            );

            let keygen = frost.new_keygen(Default::default(), &scalar_polys).unwrap();
            let mut shares = generate_keygen_shares(&frost, &keygen, &scalar_polys);
            group.bench_with_input(
                BenchmarkId::new("generate_keygen_shares", input.0),
                &input,
                |b, (_, _)| b.iter(|| generate_keygen_shares(&frost, &keygen, &scalar_polys)),
            );

            let start_time = Instant::now();
            // collect the received shares for each party
            let received_shares = scalar_polys
                .keys()
                .map(|receiver_party_index| {
                    let received = shares
                        .iter_mut()
                        .map(|(gen_party_index, (party_shares, pop))| {
                            (
                                *gen_party_index,
                                (
                                    party_shares.remove(receiver_party_index).unwrap(),
                                    pop.clone(),
                                ),
                            )
                        })
                        .collect::<BTreeMap<_, _>>();

                    (*receiver_party_index, received)
                })
                .collect::<BTreeMap<_, _>>();
            println!(
                "Time to receive (~transpose & collect) keygen shares: {:?}",
                Instant::now() - start_time
            );

            // finish keygen for each party
            let (frost_key, secret_shares) =
                finish_keygen(&frost, &keygen, received_shares.clone());
            group.bench_with_input(
                BenchmarkId::new("finish_keygen", input.0),
                &input,
                |b, (_, _)| b.iter(|| finish_keygen(&frost, &keygen, received_shares.clone())),
            );
            (frost_key, secret_shares)
        };

        let frost_key = frost_key.into_xonly_key();

        // SIGNING
        let n_signers = n_parties - threshold;
        group.throughput(Throughput::Elements(n_signers as u64));

        let signing_start = Instant::now();
        // use a boolean mask for which t participants are signers
        let mut signer_mask = vec![true; threshold];
        signer_mask.append(&mut vec![false; n_signers]);
        // shuffle the mask for random signers
        signer_mask.shuffle(&mut rng);

        let secret_shares = signer_mask
            .into_iter()
            .zip(secret_shares.into_iter())
            .filter(|(is_signer, _)| *is_signer)
            .map(|(_, secret_share)| secret_share)
            .collect::<BTreeMap<_, _>>();

        let message = Message::plain("test", b"test");

        let secret_nonces: BTreeMap<_, _> = secret_shares
            .iter()
            .map(|(signer_index, _)| (*signer_index, frost.gen_nonce(&mut rng)))
            .collect();

        let public_nonces = secret_nonces
            .iter()
            .map(|(signer_index, sn)| (*signer_index, sn.public()))
            .collect::<BTreeMap<_, _>>();

        let signing_session = frost.start_sign_session(&frost_key, public_nonces, message);

        println!(
            "Signing preparation time: {:?}",
            Instant::now() - signing_start
        );

        let signatures = sign(
            &frost,
            &frost_key,
            &signing_session,
            &secret_shares,
            &secret_nonces,
        );

        group.bench_with_input(BenchmarkId::new("sign", input.0), &input, |b, (_, _)| {
            b.iter(|| {
                sign(
                    &frost,
                    &frost_key,
                    &signing_session,
                    &secret_shares,
                    &secret_nonces,
                )
            })
        });

        let combined_sig =
            frost.combine_signature_shares(&frost_key, &signing_session, signatures.clone());
        group.bench_with_input(
            BenchmarkId::new("combine_signature_shares", input.0),
            &input,
            |b, (_, _)| {
                b.iter(|| {
                    frost.combine_signature_shares(&frost_key, &signing_session, signatures.clone())
                })
            },
        );

        assert!(frost
            .schnorr
            .verify(&frost_key.public_key(), message, &combined_sig));
    }

    group.finish();
}

criterion_group!(benches, frost_benchmark);
criterion_main!(benches);
