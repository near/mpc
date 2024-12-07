use crate::config::{ParticipantInfo, ParticipantsConfig};
use crate::indexer::lib::{get_mpc_contract_state, wait_for_contract_code, wait_for_full_sync};
use crate::primitives::ParticipantId;
use mpc_contract::ProtocolContractState;
use near_indexer_primitives::types::AccountId;
use std::collections::BTreeMap;
use std::str::FromStr;
use tokio::sync::mpsc;
use url::Url;

pub(crate) async fn read_participants_from_chain(
    mpc_contract_id: AccountId,
    port_override: Option<u16>,
    view_client: actix::Addr<near_client::ViewClientActor>,
    client: actix::Addr<near_client::ClientActor>,
    sender: mpsc::Sender<ParticipantsConfig>,
) {
    // Currently we assume the set of participants is static.
    // We wait first to catch up to the chain to avoid reading
    // the participants from an outdated state.
    wait_for_full_sync(&client).await;

    // In tests it is possible to catch up to the chain before the
    // contract is even deployed.
    wait_for_contract_code(mpc_contract_id.clone(), &view_client).await;

    let state = match get_mpc_contract_state(mpc_contract_id.clone(), &view_client).await {
        Ok(state) => state,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "error getting mpc contract state from account {:?}", mpc_contract_id);
            return;
        }
    };

    let ProtocolContractState::Running(state) = state else {
        tracing::warn!(target: "mpc", "mpc contract is not in a Running state");
        return;
    };

    tracing::info!(target: "mpc", "read mpc contract state {:?}", state);

    let _ = sender
        .send(ParticipantsConfig {
            threshold: state.threshold as u32,
            participants: convert_participant_infos(state.participants.participants, port_override),
        })
        .await;
}

fn convert_participant_infos(
    participants: BTreeMap<AccountId, mpc_contract::primitives::ParticipantInfo>,
    port_override: Option<u16>,
) -> Vec<ParticipantInfo> {
    let num_participants = participants.len();
    participants
        .into_iter()
        .zip(0..num_participants)
        .filter_map(|((_account_id, p), i)| {
            let Ok(url) = Url::parse(&p.url) else {
                tracing::error!(target: "mpc", "could not parse participant url {}", p.url);
                return None;
            };
            let Some(address) = url.host_str() else {
                tracing::error!(target: "mpc", "no host found in participant url {}", p.url);
                return None;
            };
            let Some(port) = port_override.or(url.port()) else {
                tracing::error!(target: "mpc", "no port found in participant url {}", p.url);
                return None;
            };
            // Here we need to turn the near_sdk::PublicKey used in the smart contract into a
            // near_crypto::PublicKey used by the mpc nodes. For some reason near_sdk has an
            // impl TryFrom<near_sdk::PublicKey> for near_crypto::PublicKey but it's test-only.
            // For lack of better option we use this to-string from-string conversion instead.
            let Ok(p2p_public_key) = near_crypto::PublicKey::from_str(&String::from(&p.sign_pk))
            else {
                tracing::error!(target: "mpc", "invalid participant public key {:?}", p.sign_pk);
                return None;
            };
            Some(ParticipantInfo {
                // We label the participants from 0 to N-1 by map order
                id: ParticipantId::from_raw(i as u32),
                address: address.to_string(),
                port,
                p2p_public_key,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::indexer::participants::convert_participant_infos;
    use near_indexer_primitives::types::AccountId;
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::str::FromStr;

    fn create_participant_data() -> Vec<(String, String, [u8; 32], String)> {
        vec![
            (
                "multichain-node-dev-0.testnet".to_string(),
                "http://10.101.0.56:3000".to_string(),
                [
                    90, 157, 29, 39, 252, 60, 149, 46, 122, 247, 162, 241, 200, 79, 85, 41, 40,
                    238, 194, 50, 195, 242, 195, 231, 135, 244, 161, 93, 130, 168, 41, 22,
                ],
                "ed25519:4upBpJYUrjPBzqNYaY8pvJGQtep7YMT3j9zRsopYQqfG".to_string(),
            ),
            (
                "multichain-node-dev-1.testnet".to_string(),
                "http://10.101.0.81:3000".to_string(),
                [
                    52, 159, 137, 246, 113, 122, 2, 170, 247, 166, 73, 185, 138, 199, 175, 9, 230,
                    81, 127, 253, 76, 183, 234, 138, 159, 110, 222, 232, 248, 74, 51, 12,
                ],
                "ed25519:6sqMFXkswuH9b7Pnn6dGAy1vA1X3N2CSrKDDkdHzTcrv".to_string(),
            ),
            (
                "multichain-node-dev-2.testnet".to_string(),
                "http://10.101.0.57:3000".to_string(),
                [
                    120, 174, 103, 211, 138, 250, 166, 211, 41, 187, 160, 23, 92, 32, 10, 140, 36,
                    138, 90, 130, 215, 143, 187, 143, 113, 224, 96, 230, 193, 134, 216, 0,
                ],
                "ed25519:Fru1RoC6dw1xY2J6C6ZSBUt5PEysxTLX2kDexxqoDN6k".to_string(),
            ),
        ]
    }

    fn create_chain_participant_infos(
    ) -> BTreeMap<AccountId, mpc_contract::primitives::ParticipantInfo> {
        create_participant_data()
            .iter()
            .map(|(account_id, url, cipher_pk, pk)| {
                let account_id = AccountId::from_str(account_id).unwrap();
                let url = url.to_string();
                let sign_pk = near_sdk::PublicKey::from_str(pk).unwrap();
                (
                    account_id.clone(),
                    mpc_contract::primitives::ParticipantInfo {
                        account_id,
                        url,
                        cipher_pk: *cipher_pk,
                        sign_pk,
                    },
                )
            })
            .collect()
    }

    // Check that the participant ids are assigned 0 to N-1 by AccountId order
    #[test]
    fn test_participant_ids() {
        let chain_infos = create_chain_participant_infos();
        let mut account_ids: Vec<AccountId> = vec![];
        let mut account_id_to_pk = HashMap::<AccountId, String>::default();
        for (account_id, info) in &chain_infos {
            account_ids.push(account_id.clone());
            account_id_to_pk.insert(account_id.clone(), String::from(&info.sign_pk));
        }
        assert!(account_ids.is_sorted());

        let converted = convert_participant_infos(chain_infos, None);
        let mut pk_to_participant_id = HashMap::<String, usize>::default();
        for (i, participant) in converted.into_iter().enumerate() {
            assert!(participant.id.raw() == i as u32);
            pk_to_participant_id.insert(participant.p2p_public_key.to_string(), i);
        }

        for (i, account_id) in account_ids.into_iter().enumerate() {
            let pk = account_id_to_pk.get(&account_id).unwrap();
            let participant_id = *pk_to_participant_id.get(pk).unwrap();
            assert_eq!(i, participant_id);
        }
    }

    // Check that the port override is applied
    #[test]
    fn test_port_override() {
        let chain_infos = create_chain_participant_infos();

        let converted = convert_participant_infos(chain_infos.clone(), None);
        converted.into_iter().for_each(|p| assert!(p.port == 3000));

        let with_override = convert_participant_infos(chain_infos, Some(443));
        with_override
            .into_iter()
            .for_each(|p| assert!(p.port == 443));
    }
}
