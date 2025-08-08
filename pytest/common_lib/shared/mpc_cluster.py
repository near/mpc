import base64
import hashlib
import json
import pathlib
import sys
import time


from common_lib import constants
from common_lib import signature
from common_lib.constants import TGAS
from common_lib.contract_state import ContractState, ProtocolState, SignatureScheme
from common_lib.contracts import ContractMethod
from common_lib.shared.metrics import FloatMetricName, IntMetricName
from common_lib.shared.mpc_node import MpcNode
from common_lib.shared.near_account import NearAccount
from common_lib.shared.transaction_status import assert_txn_success
from common_lib.signature import generate_sign_args

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from typing import Any, List, Optional

from transaction import sign_deploy_contract_tx


class MpcCluster:
    """Helper class"""

    def run_all(self):
        for node in self.nodes:
            node.run()

    def kill_all(self):
        for node in self.mpc_nodes:
            node.kill(False)

    def __init__(self, main: NearAccount, secondary: NearAccount):
        self.mpc_nodes: List[MpcNode] = []
        # Note: Refer to signing schemas and key resharing
        self.next_participant_id = 0
        # Main account where Chain Signatures contract is deployed
        self.contract_node = main
        # In some tests we may need another CS contract.
        self.secondary_contract_node = secondary
        # An account from which we make requests to the Chain Signatures contract
        self.sign_request_node = secondary

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

    def get_float_metric_value(
        self, metric_name: FloatMetricName
    ) -> List[Optional[float]]:
        return [node.get_float_metric_value(metric_name) for node in self.mpc_nodes]

    def get_int_metric_value(self, metric_name: IntMetricName) -> List[Optional[int]]:
        return [node.get_int_metric_value(metric_name) for node in self.mpc_nodes]

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
        tx = sign_deploy_contract_tx(key, contract, nonce + 1, last_block_hash)
        self.contract_node.send_txn_and_check_success(tx)

    def deploy_secondary_contract(self, contract):
        """
        Some tests need a second contract deployed.
        The main mpc contract is deployed to node 0's account,
        so we put the secondary contract on node 1's account.
        """
        last_block_hash = self.secondary_contract_node.last_block_hash()
        (key, nonce) = self.secondary_contract_node.get_key_and_nonce()
        tx = sign_deploy_contract_tx(key, contract, nonce + 1, last_block_hash)
        self.secondary_contract_node.send_txn_and_check_success(tx)

    def make_function_call_on_secondary_contract(self, function_name, args):
        tx = self.secondary_contract_node.sign_tx(
            self.secondary_contract_node.account_id(),
            function_name,
            args,
            gas=300 * TGAS,
        )
        return self.secondary_contract_node.near_node.send_tx_and_wait(tx, 20)

    def init_cluster(
        self,
        participants: List[MpcNode],
        threshold: int,
        domains=["Secp256k1", "Ed25519"],
    ):
        """
        initializes the contract with `participants` and `threshold`.
        Adds `Secp256k1` to the contract domains.
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
                            "url": node.url,
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
        if additional_init_args is not None:
            args.update(additional_init_args)
        tx = self.contract_node.sign_tx(self.contract_node.account_id(), "init", args)
        self.contract_node.send_txn_and_check_success(tx)
        assert self.wait_for_state("Running"), "expected running state"

    def wait_for_state(self, state: ProtocolState):
        """
        Waits until the contract is in the desired state
        """
        n_attempts = 120
        n = 0
        while not self.contract_state().is_state(state) and n < n_attempts:
            time.sleep(0.1)
            n += 1
            if n % 10 == 0:
                self.contract_state().print()

        self.contract_state().print()
        return n < n_attempts

    def add_domains(
        self,
        signature_schemes: List[SignatureScheme],
        wait_for_running=True,
    ):
        print(
            f"\033[91m(Vote Domains) Adding domains: \033[93m{signature_schemes}\033[0m"
        )
        state = self.contract_state()
        state.print()
        assert state.is_state("Running"), "require running state"
        domains_to_add = []
        next_domain_id = state.protocol_state.next_domain_id()
        for scheme in signature_schemes:
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

        assert self.wait_for_state("Initializing"), "failed to initialize"
        if wait_for_running:
            assert self.wait_for_state("Running"), "failed to run"

    def do_resharing(
        self,
        new_participants: List[MpcNode],
        new_threshold: int,
        prospective_epoch_id: int,
        wait_for_running=True,
    ):
        self.define_candidate_set(new_participants)
        print(
            f"\033[91m(Vote Resharing) Voting to reshare with new threshold: \033[93m{new_threshold}\033[0m"
        )
        args = {
            "prospective_epoch_id": prospective_epoch_id,
            "proposal": self.make_threshold_parameters(new_threshold),
        }
        state = self.contract_state()
        assert state.is_state("Running"), "Require running state"

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

        assert self.wait_for_state("Resharing"), "failed to start resharing"
        if wait_for_running:
            assert self.wait_for_state("Running"), "failed to conclude resharing"
            self.update_participant_status()

    def get_contract_state(self):
        cn = self.contract_node
        txn = cn.sign_tx(self.mpc_contract_account(), "state", {})
        res = cn.send_txn_and_check_success(txn)
        assert "error" not in res, res
        res = res["result"]["status"]["SuccessValue"]
        res = base64.b64decode(res)
        res = json.loads(res)
        return res

    def contract_state(self):
        return ContractState(self.get_contract_state())

    def make_sign_request_txns(
        self,
        requests_per_domains: int,
        nonce_offset: int = 1,
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
            print(
                f"\033[91mGenerating \033[93m{requests_per_domains}\033[91m sign requests for {domain}.\033[0m"
            )
            for _ in range(requests_per_domains):
                sign_args = generate_sign_args(domain)
                nonce_offset += 1

                tx = self.sign_request_node.sign_tx(
                    self.mpc_contract_account(),
                    "sign",
                    sign_args,
                    nonce_offset=nonce_offset,
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
        self.sign_request_node.send_await_check_txs_parallel(
            "sign request", txs, sig_verification
        )

    def propose_update(self, args):
        participant = self.mpc_nodes[0]
        tx = participant.sign_tx(
            self.mpc_contract_account(),
            ContractMethod.PROPOSE_UPDATE,
            args,
            # TODO: #771 https://github.com/near/mpc/issues/771
            deposit=10610730000000000000000000,
        )
        res = participant.send_txn_and_check_success(tx, timeout=30)
        return int(
            base64.b64decode(res["result"]["status"]["SuccessValue"])
            .decode("utf-8")
            .strip("")
        )

    def get_deployed_contract_hash(self, finality="optimistic"):
        account_id = self.mpc_contract_account()
        query = {
            "request_type": "view_code",
            "account_id": account_id,
            "finality": finality,
        }
        response = self.contract_node.near_node.json_rpc("query", query)
        assert "error" not in response, (
            f"Error fetching contract code: {response['error']}"
        )
        code_b64 = response.get("result", {}).get("code_base64", "")
        contract_code = base64.b64decode(code_b64)
        sha256_hash = hashlib.sha256(contract_code).hexdigest()
        return sha256_hash

    def vote_update(self, nodes: List[MpcNode], update_id: int):
        vote_update_args = {"id": update_id}
        self.parallel_contract_calls(
            method=ContractMethod.VOTE_UPDATE, nodes=nodes, args=vote_update_args
        )

    def assert_is_deployed(self, contract):
        hash_expected = hashlib.sha256(contract).hexdigest()
        hash_deployed = self.get_deployed_contract_hash()
        assert hash_expected == hash_deployed, "invalid contract deployed"

    def get_config(self, node_id=0):
        node = self.mpc_nodes[node_id]
        tx = node.sign_tx(self.mpc_contract_account(), "config", {})
        res = node.send_txn_and_check_success(tx)
        return json.dumps(
            json.loads(
                base64.b64decode(res["result"]["status"]["SuccessValue"]).decode(
                    "utf-8"
                )
            )
        )
