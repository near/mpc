use crate::{primitives::thresholds::ThresholdParameters, state::ProtocolContractState};

fn params_to_string(output: &mut String, parameters: &ThresholdParameters) {
    output.push_str(&format!("    Participants:\n"));
    for (account_id, id, info) in parameters.participants().participants() {
        output.push_str(&format!("      ID {}: {} ({})\n", id, account_id, info.url));
    }
    output.push_str(&format!(
        "    Threshold: {}\n",
        parameters.threshold().value()
    ));
}

pub fn protocol_state_to_string(contract_state: &ProtocolContractState) -> String {
    let mut output = String::new();
    match contract_state {
        ProtocolContractState::NotInitialized => {
            output.push_str(&format!("Contract is not initialized\n"));
        }
        ProtocolContractState::Initializing(state) => {
            output.push_str(&format!(
                "Contract is in Initializing state (key generation)"
            ));
            output.push_str(&format!("  Epoch: {}\n", state.generating_key.epoch_id()));
            output.push_str(&format!("  Domains:\n"));
            for (i, domain) in state.domains.domains().iter().enumerate() {
                output.push_str(&format!("    Domain {}: {:?}, ", domain.id, domain.scheme));
                #[allow(clippy::comparison_chain)]
                if i < state.generated_keys.len() {
                    output.push_str(&format!(
                        "key generated (attempt ID {})\n",
                        state.generated_keys[i].attempt
                    ));
                } else if i == state.generated_keys.len() {
                    output.push_str(&format!("generating key: "));
                    if state.generating_key.is_active() {
                        output.push_str(&format!(
                            "active; current attempt ID: {}\n",
                            state
                                .generating_key
                                .current_key_event_id()
                                .unwrap()
                                .attempt_id
                        ));
                    } else {
                        output.push_str(&format!(
                            "not active; next attempt ID: {}\n",
                            state.generating_key.next_attempt_id()
                        ));
                    }
                } else {
                    output.push_str(&format!("queued for generation\n"));
                }
            }
            output.push_str(&format!("  Parameters:\n"));
            params_to_string(&mut output, state.generating_key.proposed_parameters());
            output.push_str(&format!("  Warning: this tool does not calculate automatic timeouts for key generation attempts\n"));
        }
        ProtocolContractState::Running(state) => {
            output.push_str(&format!("Contract is in Running state\n"));
            output.push_str(&format!("  Epoch: {}\n", state.keyset.epoch_id));
            output.push_str(&format!("  Keyset:\n"));
            for (domain, key) in state
                .domains
                .domains()
                .iter()
                .zip(state.keyset.domains.iter())
            {
                output.push_str(&format!(
                    "    Domain {}: {:?}, key from attempt {}\n",
                    domain.id, domain.scheme, key.attempt
                ));
            }
            output.push_str(&format!("  Parameters:\n"));
            params_to_string(&mut output, &state.parameters);
        }
        ProtocolContractState::Resharing(state) => {
            output.push_str(&format!("Contract is in Resharing state\n"));
            output.push_str(&format!(
                "  Epoch transition: original {} --> prospective {}\n",
                state.previous_running_state.keyset.epoch_id,
                state.prospective_epoch_id()
            ));
            output.push_str(&format!("  Domains:\n"));
            for (i, domain) in state
                .previous_running_state
                .domains
                .domains()
                .iter()
                .enumerate()
            {
                output.push_str(&format!(
                    "    Domain {}: {:?}, original key from attempt {}, ",
                    domain.id,
                    domain.scheme,
                    state.previous_running_state.keyset.domains[i].attempt
                ));

                #[allow(clippy::comparison_chain)]
                if i < state.reshared_keys.len() {
                    output.push_str(&format!(
                        "reshared (attempt ID {})\n",
                        state.reshared_keys[i].attempt
                    ));
                } else if i == state.reshared_keys.len() {
                    output.push_str(&format!("resharing key: "));
                    if state.resharing_key.is_active() {
                        output.push_str(&format!(
                            "active; current attempt ID: {}\n",
                            state
                                .resharing_key
                                .current_key_event_id()
                                .unwrap()
                                .attempt_id
                        ));
                    } else {
                        output.push_str(&format!(
                            "not active; next attempt ID: {}\n",
                            state.resharing_key.next_attempt_id()
                        ));
                    }
                } else {
                    output.push_str(&format!("queued for resharing\n"));
                }
            }
            output.push_str(&format!("  Previous Parameters:\n"));
            params_to_string(&mut output, &state.previous_running_state.parameters);
            output.push_str(&format!("  Proposed Parameters:\n"));
            params_to_string(&mut output, state.resharing_key.proposed_parameters());

            output.push_str(&format!("  Warning: this tool does not calculate automatic timeouts for resharing attempts\n"));
        }
    }
    output
}
