from dataclasses import dataclass
from typing import Any, Optional, Dict


@dataclass
class ParticipantInfo:
    url: str
    sign_pk: str


@dataclass
class DestinationNodeInfo:
    signer_account_pk: str
    destination_node_info: ParticipantInfo


@dataclass
class BackupServiceInfo:
    public_key: str


@dataclass
class AccountEntry:
    backup_service_info: Optional[BackupServiceInfo]
    destination_node_info: Optional[DestinationNodeInfo]


@dataclass
class MigrationState:
    state_by_account: Dict[str, AccountEntry]


def parse_migration_state(contract_btree_map: Any) -> MigrationState:
    state_by_account: Dict[str, AccountEntry] = {}

    for account_id, (backup_raw, dest_raw) in contract_btree_map.items():
        backup = BackupServiceInfo(**backup_raw) if backup_raw else None
        dest = (
            DestinationNodeInfo(
                signer_account_pk=dest_raw["signer_account_pk"],
                destination_node_info=ParticipantInfo(
                    **dest_raw["destination_node_info"]
                ),
            )
            if dest_raw
            else None
        )
        state_by_account[account_id] = AccountEntry(backup, dest)

    return MigrationState(state_by_account=state_by_account)
