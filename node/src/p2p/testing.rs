use crate::config::{MpcConfig, ParticipantInfo, ParticipantsConfig};
use crate::p2p::keys::generate_keypair;
use crate::primitives::ParticipantId;
use near_crypto::{ED25519PublicKey, ED25519SecretKey};
use near_sdk::AccountId;

/// A unique seed for each integration test to avoid port conflicts during testing.
#[derive(Copy, Clone)]
pub struct PortSeed(u16);

impl PortSeed {
    pub fn p2p_port(&self, node_index: usize) -> u16 {
        (10000_usize + self.0 as usize * 100 + node_index)
            .try_into()
            .unwrap()
    }

    pub fn web_port(&self, node_index: usize) -> u16 {
        (20000_usize + self.0 as usize * 100 + node_index)
            .try_into()
            .unwrap()
    }

    pub const CLI_FOR_PYTEST: Self = Self(0);
}

#[cfg(test)]
impl PortSeed {
    // Each place that passes a PortSeed in should define a unique one here.
    pub const P2P_BASIC_TEST: Self = Self(1);
    pub const P2P_WAIT_FOR_READY_TEST: Self = Self(2);
    pub const BASIC_CLUSTER_TEST: Self = Self(3);
    pub const FAULTY_CLUSTER_TEST: Self = Self(4);
    pub const KEY_RESHARING_SIMPLE_TEST: Self = Self(5);
    pub const KEY_RESHARING_MULTISTAGE_TEST: Self = Self(6);
    pub const KEY_RESHARING_SIGNATURE_BUFFERING_TEST: Self = Self(7);
    pub const BASIC_MULTIDOMAIN_TEST: Self = Self(8);
    pub const FAULTY_STUCK_INDEXER_TEST: Self = Self(9);
}

pub fn generate_test_p2p_configs(
    participant_accounts: &[AccountId],
    threshold: usize,
    // this is a hack to make sure that when tests run in parallel, they don't
    // collide on the same port.
    port_seed: PortSeed,
    // Supply `Some` value here if you want to use pre-existing p2p key pairs
    p2p_keypairs: Option<Vec<(ED25519SecretKey, ED25519PublicKey)>>,
) -> anyhow::Result<Vec<(MpcConfig, ED25519SecretKey)>> {
    let p2p_keypairs = if let Some(p2p_keypairs) = p2p_keypairs {
        p2p_keypairs
    } else {
        participant_accounts
            .iter()
            .map(|_account_id| generate_keypair())
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut participants = Vec::new();
    for (i, (participant_account, (_p2p_secret_key, p2p_public_key))) in participant_accounts
        .iter()
        .zip(p2p_keypairs.iter())
        .enumerate()
    {
        participants.push(ParticipantInfo {
            id: ParticipantId::from_raw(rand::random()),
            address: "127.0.0.1".to_string(),
            port: port_seed.p2p_port(i),
            p2p_public_key: near_crypto::PublicKey::ED25519(p2p_public_key.clone()),
            near_account_id: participant_account.clone(),
        });
    }

    let mut configs = Vec::new();
    for (i, keypair) in p2p_keypairs.into_iter().enumerate() {
        let participants = ParticipantsConfig {
            threshold: threshold as u64,
            participants: participants.clone(),
        };

        let mpc_config = MpcConfig {
            my_participant_id: participants.participants[i].id,
            participants,
        };
        configs.push((mpc_config, keypair.0));
    }

    Ok(configs)
}
