import base64
from dataclasses import asdict
import json
import pathlib
import sys
import time
from concurrent.futures import ThreadPoolExecutor


from common_lib import constants
from common_lib import signature
from common_lib import ckd
from common_lib.constants import TGAS
from common_lib.contract_state import (
    ContractState,
    ProtocolState,
    SignatureScheme,
    RunningProtocolState,
)
from common_lib.contracts import ContractMethod
from common_lib.migration_state import (
    BackupServiceInfo,
    DestinationNodeInfo,
    MigrationState,
    parse_migration_state,
)
from common_lib.shared.metrics import IntMetricName
from common_lib.shared.mpc_node import MpcNode
from common_lib.shared.near_account import NearAccount
from common_lib.shared.transaction_status import assert_txn_success
from common_lib.signature import generate_sign_args
from common_lib.ckd import generate_ckd_args
from common_lib.constants import TRANSACTION_TIMEOUT

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from typing import Any, List, Optional

from transaction import sign_deploy_contract_tx


class MpcCluster:
    """Helper class"""

    def kill_all(self):
        with ThreadPoolExecutor(max_workers=len(self.mpc_nodes)) as executor:
            executor.map(lambda node: node.kill(False), self.mpc_nodes)

    def kill_nodes(self, node_idxs: List[int], gentle=True):
        """
        Kills nodes with indexes `node_idxs`
        """
        for node_idx in node_idxs:
            self.mpc_nodes[node_idx].kill(gentle)

    def run_nodes(self, node_idxs: List[int]):
        """
        Starts nodes with indexes `node_idxs`
        """
        for node_idx in node_idxs:
            self.mpc_nodes[node_idx].run()

    def set_block_ingestion(self, node_idxs: List[int], active: bool):
        for node_idx in node_idxs:
            self.mpc_nodes[node_idx].set_block_ingestion(active)

    def reset_mpc_data(self, node_idxs: List[int]):
        for node_idx in node_idxs:
            self.mpc_nodes[node_idx].reset_mpc_data()

    def __init__(self, main: NearAccount, secondary: Optional[NearAccount] = None):
        self.mpc_nodes: List[MpcNode] = []
        # Note: Refer to signing schemas and key resharing
        self.next_participant_id: int = 0
        # Main account where Chain Signatures contract is deployed
        self.contract_node = main
        # In some tests we may need another CS contract.
        self.secondary_contract_node = secondary or main
        # An account from which we make requests to the Chain Signatures contract
        self.request_node = main

    def print_cluster_status(self):
        status_list = [node.print() for node in self.mpc_nodes]
        print("Cluster status:", " ".join(status_list))

    def get_voters(self):
        voters = [
            node
            for node in self.mpc_nodes
            if node.is_running
            and (
                node.status == MpcNode.NodeStatus.OLD_PARTICIPANT
                or node.status == MpcNode.NodeStatus.PARTICIPANT
            )
        ]
        print("Voters:", " | ".join([node.print() for node in voters]))
        return voters

    def mpc_contract_account(self):
        return self.contract_node.account_id()

    def get_int_metric_value(self, metric_name: IntMetricName) -> List[Optional[int]]:
        return [node.get_int_metric_value(metric_name) for node in self.mpc_nodes]

    def require_int_metric_values(self, metric_name: IntMetricName) -> List[int]:
        """
        Returns the integer values of the metric `metric_name`. Panics if any of the metrics is None.
        """
        return [node.require_int_metric_value(metric_name) for node in self.mpc_nodes]

    def get_int_metric_value_for_node(self, metric_name, node_index):
        return self.mpc_nodes[node_index].metrics.get_int_metric_value(metric_name)

    def parallel_contract_calls(
        self,
        method: ContractMethod,
        nodes: List[MpcNode],
        args: dict[str, Any],
    ):
        txns = [
            node.sign_tx(self.mpc_contract_account(), method, args) for node in nodes
        ]
        self.contract_node.send_await_check_txs_parallel(
            method, txns, assert_txn_success
        )

    def deploy_contract(self, contract):
        """
        Deploy the MPC contract.
        """
        last_block_hash = self.contract_node.last_block_hash()
        (key, nonce) = self.contract_node.get_key_and_nonce()
        tx = sign_deploy_contract_tx(key, contract, nonce, last_block_hash)
        self.contract_node.send_txn_and_check_success(tx)

    def deploy_secondary_contract(self, contract):
        """
        Some tests need a second contract deployed.
        The main mpc contract is deployed to node 0's account,
        so we put the secondary contract on node 1's account.
        """
        last_block_hash = self.secondary_contract_node.last_block_hash()
        (key, nonce) = self.secondary_contract_node.get_key_and_nonce()
        tx = sign_deploy_contract_tx(key, contract, nonce, last_block_hash)
        self.secondary_contract_node.send_txn_and_check_success(tx)

    def make_function_call_on_secondary_contract(self, function_name, args):
        tx = self.secondary_contract_node.sign_tx(
            self.secondary_contract_node.account_id(),
            function_name,
            args,
            gas=300 * TGAS,
        )
        return self.secondary_contract_node.near_node.send_tx_and_wait(
            tx, timeout=TRANSACTION_TIMEOUT
        )

    def init_cluster(
        self,
        participants: List[MpcNode],
        threshold: int,
        domains=["Secp256k1", "Ed25519", "Bls12381"],
    ):
        """
        initializes the contract with `participants` and `threshold`.
        Adds `Secp256k1`, `Ed25519` and `Bls12381` to the contract domains.
        """
        self.define_candidate_set(participants)
        self.update_participant_status(
            assert_contract=False
        )  # do not assert when contract is not initialized
        self.init_contract(threshold=threshold)
        self.add_domains(domains)

    def define_candidate_set(self, mpc_nodes: List[MpcNode]):
        """
        Labels mpc_nodes as a candidate. Any node that is currently a participant but not in `mpc_nodes` will be labeled a `old_participant`
        """
        for node in mpc_nodes:
            if node not in self.mpc_nodes:
                node.participant_id = self.next_participant_id
                node.status = MpcNode.NodeStatus.NEW_PARTICIPANT
                print(
                    f"MpcCluster: Adding node {node.account_id()} as participant {node.participant_id}"
                )
                self.next_participant_id += 1

        for node in self.mpc_nodes:
            if node not in mpc_nodes:
                print(f"MpcCluster: Kicking out node {node.account_id()}")
                node.participant_id = None
                node.status = MpcNode.NodeStatus.OLD_PARTICIPANT
        self.mpc_nodes = mpc_nodes
        self.print_cluster_status()

    def update_participant_status(self, assert_contract=True):
        """
        any old participants are removed from the set of nodes.
        any new participants are now `participants`
        if assert_contract is True, then it ensures the set is consistent with the contract
        """
        nodes = []
        for node in self.mpc_nodes:
            if node.status == MpcNode.NodeStatus.OLD_PARTICIPANT:
                node.status = MpcNode.NodeStatus.IDLE
            elif node.status == MpcNode.NodeStatus.NEW_PARTICIPANT:
                node.status = MpcNode.NodeStatus.PARTICIPANT
                nodes.append(node)
            elif node.status == MpcNode.NodeStatus.PARTICIPANT:
                nodes.append(node)
        self.nodes = nodes
        if assert_contract:
            contract_state = self.contract_state()
            assert isinstance(contract_state.protocol_state, RunningProtocolState)
            assert len(
                contract_state.protocol_state.parameters.participants.participants
            ) == len(self.mpc_nodes)
            for p in self.mpc_nodes:
                assert contract_state.protocol_state.parameters.participants.is_participant(
                    p.account_id()
                )

        self.print_cluster_status()

    def make_threshold_parameters(self, threshold: int):
        return {
            "threshold": threshold,
            "participants": {
                "next_id": self.next_participant_id,
                "participants": [
                    [
                        node.account_id(),
                        node.participant_id,
                        {
                            "sign_pk": node.p2p_public_key,
                            "url": node.p2p_url,
                        },
                    ]
                    for node in self.mpc_nodes
                ],
            },
        }

    def init_contract(self, threshold, additional_init_args=None):
        """
        Initializes the contract by calling init. This needs to be done before
        the contract is usable.
        """
        args = {"parameters": self.make_threshold_parameters(threshold)}
        print(f"arg: {args}\n")
        if additional_init_args is not None:
            args.update(additional_init_args)
        tx = self.contract_node.sign_tx(self.contract_node.account_id(), "init", args)
        self.contract_node.send_txn_and_check_success(tx)
        assert self.wait_for_state(ProtocolState.RUNNING), "expected running state"

    def wait_for_state(self, state: ProtocolState):
        """
        Waits until the contract is in the desired state
        """
        n_attempts = 120
        n = 0
        contract_state = self.contract_state()
        time.sleep(0.2)
        while not contract_state.is_state(state) and n < n_attempts:
            n += 1
            if n % 10 == 0:
                contract_state.print()
            contract_state = self.contract_state()
            time.sleep(0.2)

        # Note: without this line, or by doing `contract_state.print()` instead,
        # tests fail with:
        # >       assert nonce is not None
        # E       AssertionError
        # common_lib/shared/near_account.py:105: AssertionError
        self.contract_state().print()
        return n < n_attempts

    def add_domains(
        self,
        schemes: List[SignatureScheme],
        wait_for_running=True,
    ):
        print(f"\033[91m(Vote Domains) Adding domains: \033[93m{schemes}\033[0m")
        state = self.contract_state()
        state.print()
        assert state.is_state(ProtocolState.RUNNING), "require running state"
        assert isinstance(state.protocol_state, RunningProtocolState)
        domains_to_add = []
        next_domain_id = state.protocol_state.next_domain_id()
        for scheme in schemes:
            domains_to_add.append(
                {
                    "id": next_domain_id,
                    "scheme": scheme,
                }
            )
            next_domain_id += 1
        args = {
            "domains": domains_to_add,
        }

        self.parallel_contract_calls(
            method=ContractMethod.VOTE_ADD_DOMAINS,
            nodes=self.get_voters(),
            args=args,
        )

        assert self.wait_for_state(ProtocolState.INITIALIZING), "failed to initialize"
        if wait_for_running:
            assert self.wait_for_state(ProtocolState.RUNNING), "failed to run"

    def do_resharing(
        self,
        new_participants: List[MpcNode],
        new_threshold: int,
        prospective_epoch_id: int,
        wait_for_running=True,
    ):
        assert self.wait_for_nodes_to_have_attestation(new_participants), (
            "all participants must have a valid TEE attestation for a resharing proposal to pass"
        )

        self.define_candidate_set(new_participants)
        print(
            f"\033[91m(Vote Resharing) Voting to reshare with new threshold: \033[93m{new_threshold}\033[0m"
        )
        args = {
            "prospective_epoch_id": prospective_epoch_id,
            "proposal": self.make_threshold_parameters(new_threshold),
        }
        state = self.contract_state()
        assert state.is_state(ProtocolState.RUNNING), "Require running state"

        self.parallel_contract_calls(
            method=ContractMethod.VOTE_NEW_PARAMETERS,
            nodes=self.get_voters(),
            args=args,
        )
        added_participants = [
            node for node in new_participants if node not in self.get_voters()
        ]
        self.parallel_contract_calls(
            method=ContractMethod.VOTE_NEW_PARAMETERS,
            nodes=added_participants,
            args=args,
        )

        assert self.wait_for_state(ProtocolState.RESHARING), "failed to start resharing"
        if wait_for_running:
            assert self.wait_for_state(ProtocolState.RUNNING), (
                "failed to conclude resharing"
            )
            self.update_participant_status()

    def view_contract_function(
        self, function_name: str, args: dict[str, Any] | None = None
    ) -> Any:
        if args is None:
            args = {}
        encoded_args = base64.b64encode(json.dumps(args).encode("utf-8")).decode("utf-8")
        res = self.contract_node.near_node.call_function(
            self.mpc_contract_account(),
            function_name,
            encoded_args,
            timeout=10,
        )
        assert "error" not in res, res
        result = bytes(res["result"]["result"]).decode("utf-8")
        return json.loads(result)

    def call_contract_function_with_account_assert_success(
        self, account: NearAccount, function_name: str, args: dict = {}
    ) -> Any:
        txn = account.sign_tx(self.mpc_contract_account(), function_name, args)
        res = account.send_txn_and_check_success(txn)
        assert "error" not in res, res
        res = res["result"]["status"]["SuccessValue"]
        res = base64.b64decode(res)
        res = json.loads(res)
        return res

    def call_contract_function_assert_success(
        self, function_name: str, args: dict = {}
    ) -> Any:
        return self.call_contract_function_with_account_assert_success(
            self.contract_node, function_name, args
        )

    def get_contract_state(self) -> Any:
        res = self.call_contract_function_assert_success(ContractMethod.STATE)
        return res

    def get_migrations(self) -> MigrationState:
        res = self.call_contract_function_assert_success(ContractMethod.MIGRATION_INFO)
        return parse_migration_state(res)

    def get_tee_approved_accounts(self) -> List[str]:
        node_ids = self.call_contract_function_assert_success(
            ContractMethod.GET_TEE_ACCOUNTS
        )
        tls_public_keys = [node_id["tls_public_key"] for node_id in node_ids]
        return tls_public_keys

    def wait_for_nodes_to_have_attestation(self, participants: List[MpcNode]) -> bool:
        n_attempts = 120
        n = 0

        participant_tls_keys = [
            participant.p2p_public_key for participant in participants
        ]

        participant_tls_keys = set(participant_tls_keys)

        while n <= n_attempts:
            tls_keys_with_attestation = set(self.get_tee_approved_accounts())
            all_participants_have_attestation_submitted = (
                tls_keys_with_attestation.issuperset(participant_tls_keys)
            )

            if all_participants_have_attestation_submitted:
                return True

            time.sleep(0.1)
            n += 1
            if n % 10 == 0:
                print(
                    f"TLS keys with attestation: {tls_keys_with_attestation}. TLS keys missing attestation: {participant_tls_keys - tls_keys_with_attestation}"
                )
                self.contract_state().print()

        return False

    def contract_state(self):
        return ContractState(self.get_contract_state())

    def make_sign_request_txns(
        self,
        requests_per_domains: int,
        add_gas: Optional[int] = None,
        add_deposit: Optional[int] = None,
    ):
        """
        Creates signature transactions for each domain and request count pair.

        Returns:
            A list of signed transactions
        """
        txs = []
        gas = constants.GAS_FOR_SIGN_CALL * TGAS + (add_gas or 0)
        deposit = constants.SIGNATURE_DEPOSIT + (add_deposit or 0)
        domains = self.contract_state().get_running_domains()
        for domain in domains:
            if domain.scheme == "Secp256k1" or domain.scheme == "Ed25519":
                print(
                    f"\033[91mGenerating \033[93m{requests_per_domains}\033[91m sign requests for {domain}.\033[0m"
                )
                for _ in range(requests_per_domains):
                    sign_args = generate_sign_args(domain)

                    tx = self.request_node.sign_tx(
                        self.mpc_contract_account(),
                        "sign",
                        sign_args,
                        deposit=deposit,
                        gas=gas,
                    )
                    txs.append(tx)
        return txs

    def send_and_await_signature_requests(
        self,
        requests_per_domains: int,
        sig_verification=signature.assert_signature_success,
        add_gas: Optional[int] = None,
        add_deposit: Optional[int] = None,
    ):
        """
        Sends signature requests, waits for the results and validates them with `sig_verification`.

        Raises:
            AssertionError:
                - If the indexers fail to observe the signature requests before `constants.TIMEOUT` is reached.
                - If `sig_verification` raises an AssertionError.
        """
        txs = self.make_sign_request_txns(
            requests_per_domains, add_gas=add_gas, add_deposit=add_deposit
        )
        self.request_node.send_await_check_txs_parallel(
            "sign request", txs, sig_verification
        )

    def make_ckd_request_txns(
        self,
        requests_per_domains: int,
        add_gas: Optional[int] = None,
        add_deposit: Optional[int] = None,
    ):
        """
        Creates ckd transactions for each domain and request count pair.

        Returns:
            A list of signed transactions
        """
        txs = []
        gas = constants.GAS_FOR_CKD_CALL * TGAS + (add_gas or 0)
        deposit = constants.CKD_DEPOSIT + (add_deposit or 0)
        domains = self.contract_state().get_running_domains()
        for domain in domains:
            if domain.scheme == "Bls12381":
                print(
                    f"\033[91mGenerating \033[93m{requests_per_domains}\033[91m ckd requests for {domain}.\033[0m"
                )
                for i in range(requests_per_domains):
                    ckd_args = generate_ckd_args(domain)

                    tx = self.request_node.sign_tx(
                        self.mpc_contract_account(),
                        "request_app_private_key",
                        ckd_args,
                        deposit=deposit,
                        gas=gas,
                    )
                    txs.append(tx)
        return txs

    def send_and_await_ckd_requests(
        self,
        requests_per_domains: int,
        ckd_verification=ckd.assert_ckd_success,
        add_gas: Optional[int] = None,
        add_deposit: Optional[int] = None,
    ):
        """
        Sends ckd requests, waits for the results and validates them with `ckd_verification`.

        Raises:
            AssertionError:
                - If the indexers fail to observe the ckd requests before `constants.TIMEOUT` is reached.
                - If `ckd_verification` raises an AssertionError.
        """
        txs = self.make_ckd_request_txns(
            requests_per_domains, add_gas=add_gas, add_deposit=add_deposit
        )
        self.request_node.send_await_check_txs_parallel(
            "ckd request", txs, ckd_verification
        )

    def register_backup_service_info(
        self, node_id: int, backup_service_info: BackupServiceInfo
    ):
        node = self.mpc_nodes[node_id]
        args = {"backup_service_info": asdict(backup_service_info)}
        res = self.call_contract_function_with_account_assert_success(
            node, ContractMethod.REGISTER_BACKUP_SERVICE, args
        )
        return json.dumps(res)

    def start_node_migration(
        self, node_id: int, destination_node_info: DestinationNodeInfo
    ):
        node = self.mpc_nodes[node_id]
        args = {"destination_node_info": asdict(destination_node_info)}
        res = self.call_contract_function_with_account_assert_success(
            node, ContractMethod.START_NODE_MIGRATION, args
        )
        return json.dumps(res)
