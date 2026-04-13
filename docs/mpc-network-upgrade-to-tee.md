
# MPC Network Upgrade from Non TEE to TEE

The approach is to support a 2 phase upgrade process.

**First contract upgrade:**

The contract will support both TEE and non TEE participants.  
If a node submitted a remote attestation to the contract, it must be valid, otherwise he can not join the network.  
But we will also allow participants to join without summiting remote attestation.  In this phase, all participants, **one by one**, will be moved to a TDX based MPC node. 

Then they will be removed from the network and added again while submitting their remote attestation

*Note - The move to TDX based MPC node, will force a change in the TLS and node account keys, therefor the removal and re-adding from the contract is necessary.*  
After all node have been migrated to TDX, and network is deemed stable (enough time has passed and enough test have been run). We will move to the second phase.


**Second contract upgrade**

In this upgrade, the contract will enforce that only nodes with valid remote attestation can join the network. 

In addition, any node without a valid attestation will be kick out.

TODO: there is an alternative option in discussion.
