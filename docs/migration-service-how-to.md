# Migration Service Howto

Node operators are responsible for:
1. **Registering Backup Service**: Call `register_backup_service()` to store the backup service's public key in the contract
2. **Initiating Migration**: Call `start_node_migration()` with the new node's `ParticipantInfo` when migrating to new hardware
3. **Running Backup Service** (Soft Launch): Execute `backup-cli` scripts to backup and restore keyshares during migrations
4. **Managing Environment Variables**: Ensure `MPC_BACKUP_ENCRYPTION_KEY_HEX` is consistently set on both MPC node and `backup-cli`

> **Hard Launch**: In hard launch, the backup service runs autonomously in a TEE and requires no manual intervention from operators beyond initial registration.
