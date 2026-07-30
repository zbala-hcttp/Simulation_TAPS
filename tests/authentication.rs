//! Tests for the transport layer's authentication.
//!
//! Every actor's peer keys come from the Authority (the PKI), pinned via the
//! trust anchor. These tests check that a package signed by the wrong key is
//! rejected, rather than accepted because it happens to be self-consistent.

use simulation_taps::authority::{ActorKeys, Authority};
use simulation_taps::combiner::Combiner;
use simulation_taps::network::AuthorityAnchor;
use simulation_taps::signer::Signer;

const N: usize = 3;
const T: usize = 2;

struct Party {
    auth: Authority,
    combiner: Combiner,
    signers: Vec<Signer>,
}

/// Runs the real bootstrap: Authority issues packages, everyone loads them.
fn bootstrap() -> Party {
    let auth = Authority::new(N);
    let anchor = auth.anchor();

    let mut combiner = Combiner::new();
    let mut signers: Vec<Signer> = (0..N).map(Signer::new).collect();

    let combiner_keys = ActorKeys {
        identity_pk: combiner.identity_kp.pk,
        transport_pk: combiner.transport_kp.pk,
    };

    let signer_keys: Vec<ActorKeys> = signers
        .iter()
        .map(|s| ActorKeys {
            identity_pk: s.identity_kp.pk,
            transport_pk: s.transport_kp.pk,
        })
        .collect();

    let quorum = auth.keys.set_quorum(T);
    let pkg = auth.prepare_combiner_package(
        quorum,
        N,
        T,
        signer_keys,
        &combiner.transport_kp.pk,
    );
    combiner
        .load_from_authority(&pkg, &anchor)
        .expect("combiner bootstrap must succeed");

    for (i, signer) in signers.iter_mut().enumerate() {
        let pkg = auth.prepare_signer_package(i, combiner_keys, &signer.transport_kp.pk);
        signer
            .load_from_authority(&pkg, &anchor)
            .expect("signer bootstrap must succeed");
    }

    Party {
        auth,
        combiner,
        signers,
    }
}

#[test]
fn honest_commitment_is_accepted() {
    let mut p = bootstrap();

    let pkg = p.signers[0]
        .set_commitment()
        .expect("signer 0 must be able to commit");

    assert!(
        p.combiner.load_commitment(&0, &pkg).is_ok(),
        "A genuine commitment from signer 0 must be accepted"
    );
}

#[test]
fn commitment_submitted_under_another_signers_id_is_rejected() {
    let mut p = bootstrap();

    // Signer 1 produces a perfectly well-formed, correctly signed package - but
    // it is offered to the combiner as if it came from signer 0. Because the
    // combiner checks it against the identity key the Authority registered for
    // id 0, it must not be accepted.
    let pkg = p.signers[1].set_commitment().expect("signer 1 commits");

    assert!(
        p.combiner.load_commitment(&0, &pkg).is_err(),
        "A package from signer 1 must not be accepted as signer 0"
    );
}

#[test]
fn commitment_from_an_unregistered_signer_is_rejected() {
    let mut p = bootstrap();

    // An outsider who never registered with the Authority. It can sign its own
    // package consistently, which is exactly the case that used to slip through.
    let mut rogue = Signer::new(0);
    let combiner_keys = ActorKeys {
        identity_pk: p.combiner.identity_kp.pk,
        transport_pk: p.combiner.transport_kp.pk,
    };
    let anchor = p.auth.anchor();
    let pkg = p
        .auth
        .prepare_signer_package(0, combiner_keys, &rogue.transport_kp.pk);
    rogue.load_from_authority(&pkg, &anchor).unwrap();

    let rogue_pkg = rogue.set_commitment().expect("rogue commits");

    assert!(
        p.combiner.load_commitment(&0, &rogue_pkg).is_err(),
        "A package from an unregistered signer must be rejected"
    );
}

#[test]
fn share_submitted_under_another_signers_id_is_rejected() {
    let mut p = bootstrap();

    // Drive the protocol far enough that the combiner can broadcast a challenge.
    for i in 0..N {
        let pkg = p.signers[i].set_commitment().unwrap();
        p.combiner.load_commitment(&i, &pkg).unwrap();
    }
    p.combiner.compute_aggregated_nonce().unwrap();
    p.combiner.encrypt_threshold().unwrap();
    p.combiner.compute_parameters(b"auth test").unwrap();

    let challenge = p.combiner.prepare_signer_package();

    let share_1 = p.signers[1].set_sigma(&challenge).unwrap();

    assert!(
        p.combiner.load_sigma(&0, &share_1).is_err(),
        "A share from signer 1 must not be accepted as signer 0"
    );
    assert!(
        p.combiner.load_sigma(&1, &share_1).is_ok(),
        "...but it must be accepted under its own id"
    );
}

#[test]
fn signer_rejects_a_challenge_not_signed_by_the_combiner() {
    let mut p = bootstrap();

    // A second, independent world: its own combiner and its own signers. Its
    // challenge broadcast is perfectly well-formed and correctly signed - just
    // not by the combiner our signer was told to expect.
    let shadow = bootstrap();
    let mut impostor = shadow.combiner;
    let mut shadow_signers = shadow.signers;

    for i in 0..N {
        let pkg = shadow_signers[i].set_commitment().unwrap();
        impostor.load_commitment(&i, &pkg).unwrap();
    }
    impostor.compute_aggregated_nonce().unwrap();
    impostor.encrypt_threshold().unwrap();
    impostor.compute_parameters(b"auth test").unwrap();

    let fake_challenge = impostor.prepare_signer_package();

    // The shadow world's own signers accept it...
    assert!(
        shadow_signers[0].set_sigma(&fake_challenge).is_ok(),
        "Sanity check: the challenge is itself well-formed"
    );

    // ...but ours must not.
    assert!(
        p.signers[0].set_sigma(&fake_challenge).is_err(),
        "A challenge signed by an impostor combiner must be rejected"
    );
}

#[test]
fn bootstrap_against_a_wrong_trust_anchor_is_rejected() {
    let auth = Authority::new(N);
    let other = Authority::new(N);

    let mut combiner = Combiner::new();
    let signer_keys = vec![
        ActorKeys {
            identity_pk: combiner.identity_kp.pk,
            transport_pk: combiner.transport_kp.pk,
        };
        N
    ];
    let quorum = auth.keys.set_quorum(T);
    let pkg =
        auth.prepare_combiner_package(quorum, N, T, signer_keys, &combiner.transport_kp.pk);

    // Right package, wrong pinned identity key: must not load.
    let wrong_anchor = AuthorityAnchor {
        identity_pk: other.identity_kp.pk,
        transport_pk: auth.transport_kp.pk,
    };

    assert!(
        combiner.load_from_authority(&pkg, &wrong_anchor).is_err(),
        "A package must not load against a different Authority identity key"
    );
}
