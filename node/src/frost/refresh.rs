//! Wrapper for Frost `refresh` algorithm:
//! Any subset of `>= threshold` participants can generate new secret shares, with the same group's public key.
//! This can be useful when we want to exclude a participant from a signing schema.
//!
//! As a result each participant of the protocol receives new instance of `KeygenOutput`.

use crate::frost::{to_frost_identifier, KeygenOutput};
use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use cait_sith::participants::{ParticipantCounter, ParticipantList};
use cait_sith::protocol::{
    make_protocol, Context, Participant, Protocol, ProtocolError, SharedChannel,
};
use frost_ed25519::keys::dkg::{round1, round2};
use frost_ed25519::Identifier;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;

pub fn refresh_internal<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    participants: Vec<Participant>,
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
) -> anyhow::Result<impl Protocol<Output = KeygenOutput>> {
    if participants.len() < threshold {
        anyhow::bail!("Threshold must be less than or equal to number of participants");
    }
    {
        let Some(participants) = ParticipantList::new(&participants) else {
            anyhow::bail!("Participants list contains duplicates")
        };

        if !participants.contains(me) {
            anyhow::bail!("Participant list must contain this participant");
        }
    }

    let ctx = Context::new();
    let fut = do_refresh(
        ctx.shared_channel(),
        rng,
        participants,
        me,
        keygen_output,
        threshold,
    );
    Ok(make_protocol(ctx, fut))
}

pub(crate) async fn do_refresh<RNG: CryptoRng + RngCore + 'static + Send>(
    mut chan: SharedChannel,
    rng: RNG,
    participants: Vec<Participant>,
    me: Participant,
    keygen_output: KeygenOutput,
    threshold: usize,
) -> Result<KeygenOutput, ProtocolError> {
    let participants = ParticipantList::new(&participants).unwrap(); // TODO;

    // --- Round 1
    let (round1_secret, round1_packages) =
        handle_round1(&mut chan, &participants, threshold, me, rng).await?;

    // --- Round 2
    let (round2_secret, round2_packages) = handle_round2(
        &mut chan,
        &participants,
        round1_secret,
        &round1_packages,
        me,
    )
        .await?;

    // --- Final Key Package Generation
    let (key_package, public_key_package) = frost_core::keys::refresh::refresh_dkg_shares(
        &round2_secret,
        &round1_packages,
        &round2_packages,
        keygen_output.public_key_package,
        keygen_output.key_package,
    )
        .map_err(|e| ProtocolError::AssertionFailed(format!("keyshare::part3: {:?}", e)))?;

    Ok(KeygenOutput {
        key_package,
        public_key_package,
    })
}

async fn handle_round1<RNG: CryptoRng + RngCore + 'static + Send>(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    threshold: usize,
    me: Participant,
    rng: RNG,
) -> Result<(round1::SecretPackage, BTreeMap<Identifier, round1::Package>), ProtocolError> {
    let (round1_secret, my_round1_package) = frost_core::keys::refresh::refresh_dkg_part_1(
        to_frost_identifier(me),
        participants.len() as u16,
        threshold as u16,
        rng,
    )
    .map_err(|e| ProtocolError::AssertionFailed(format!("keyshare::part1: {:?}", e)))?;

    let round1_wait_point = chan.next_waitpoint();

    chan.send_many(round1_wait_point, &my_round1_package).await;

    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let round1_packages: BTreeMap<Identifier, round1::Package> =
        collect_packages(chan, &mut seen, round1_wait_point).await?;

    Ok((round1_secret, round1_packages))
}

async fn handle_round2(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    round1_secret: round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
    me: Participant,
) -> Result<(round2::SecretPackage, BTreeMap<Identifier, round2::Package>), ProtocolError> {
    let from_frost_identifiers = Vec::from(participants.clone())
        .iter()
        .map(|&p| (to_frost_identifier(p), p))
        .collect::<BTreeMap<_, _>>();

    let (round2_secret, my_round2_packages) =
        frost_core::keys::refresh::refresh_dkg_part2(round1_secret, round1_packages)
            .map_err(|e| ProtocolError::AssertionFailed(format!("keyshare::part2: {:?}", e)))?;

    let round2_wait_point = chan.next_waitpoint();

    for (identifier, round2_package) in my_round2_packages {
        chan.send_private(
            round2_wait_point,
            from_frost_identifiers[&identifier],
            &round2_package,
        )
        .await;
    }

    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let round2_packages: BTreeMap<Identifier, round2::Package> =
        collect_packages(chan, &mut seen, round2_wait_point).await?;

    Ok((round2_secret, round2_packages))
}

pub(crate) async fn collect_packages<P: Clone + DeserializeOwned>(
    chan: &SharedChannel,
    seen: &mut ParticipantCounter<'_>,
    wait_point: u64,
) -> Result<BTreeMap<Identifier, P>, ProtocolError> {
    let mut packages = BTreeMap::new();
    while !seen.full() {
        let (from, package): (_, P) = chan.recv(wait_point).await?;
        if seen.put(from) {
            packages.insert(to_frost_identifier(from), package);
        }
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::tests::{assert_public_key_invariant, assert_signing_schema_threshold_holds, build_key_packages_with_dealer, reconstruct_signing_key};

    pub(crate) fn build_and_run_refresh_protocol(
        participants: &[(Participant, KeygenOutput)],
        threshold: usize,
    ) -> anyhow::Result<Vec<(Participant, KeygenOutput)>> {
        use cait_sith::protocol::run_protocol;
        use rand::prelude::StdRng;
        use rand::SeedableRng;

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
            Vec::with_capacity(participants.len());

        let participants_list = participants.iter().map(|(id, _)| *id).collect::<Vec<_>>();

        for (participant, key_pair) in participants {
            let rng: StdRng = StdRng::seed_from_u64(protocols.len() as u64);

            let protocol = refresh_internal(
                rng,
                participants_list.clone(),
                threshold,
                *participant,
                key_pair.clone(),
            )?;
            let protocol = Box::new(protocol);

            protocols.push((*participant, protocol))
        }

        Ok(run_protocol(protocols)?)
    }

    /// Validate that refresh protocol is indeed refresh secret shares.
    fn assert_secret_shares_updated(
        old_participants: &[(Participant, KeygenOutput)],
        new_participants: &[(Participant, KeygenOutput)]
    ) -> anyhow::Result<()> {
        let old_secret_shares = old_participants.iter().cloned().collect::<BTreeMap<_, _>>();

        for (participant, key_pair) in new_participants {
            if let Some(old_secret_share) = old_secret_shares.get(participant) {
                if old_secret_share.key_package.signing_share() == key_pair.key_package.signing_share() {
                    anyhow::bail!("secret share is the same for participant");
                }
            }
        }

        Ok(())
    }

    /// Do refresh, validate result and return to be able to chain up computations.
    fn do_test(
        participants_old: Option<Vec<(Participant, KeygenOutput)>>,
        participants_count: usize,
        threshold: usize,
        to_exclude: usize,
    ) -> anyhow::Result<Vec<(Participant, KeygenOutput)>> {
        let participants_old = participants_old.unwrap_or_else(|| build_key_packages_with_dealer(participants_count, threshold));
        let signing_key = reconstruct_signing_key(&participants_old)?;

        let new_participants = build_and_run_refresh_protocol(
            participants_old
                .iter()
                .take(participants_count - to_exclude)
                .cloned()
                .collect::<Vec<_>>()
                .as_slice(),
            threshold,
        )?;

        assert_public_key_invariant(new_participants.as_slice())?;
        assert_signing_schema_threshold_holds(signing_key, threshold, new_participants.as_slice())?;
        assert_secret_shares_updated(participants_old.as_slice(), new_participants.as_slice())?;

        Ok(new_participants)
    }

    #[test]
    fn test_refresh() -> anyhow::Result<()> {
        let participants_count = 4;
        let threshold = 3;
        let to_exclude = 0;
        do_test(None, participants_count, threshold, to_exclude)?;
        Ok(())
    }

    #[test]
    fn exclude_one() -> anyhow::Result<()> {
        let participants_count = 4;
        let threshold = 3;
        let to_exclude = 1;
        do_test(None, participants_count, threshold, to_exclude)?;
        Ok(())
    }

    #[test]
    fn exclude_three() -> anyhow::Result<()> {
        let participants_count = 6;
        let threshold = 3;
        let to_exclude = 3;
        do_test(None, participants_count, threshold, to_exclude)?;
        Ok(())
    }


    #[test]
    fn exclude_by_one_sequentially() -> anyhow::Result<()> {
        let participants_count = 5;
        let threshold = 3;

        let mut participants = None;

        for _ in 0..participants_count - threshold {
            let new_participants = do_test(participants, participants_count, threshold, 1)?;
            participants = Some(new_participants);
        }

        Ok(())
    }
}
