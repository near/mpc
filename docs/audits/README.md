# Security Audits

Every feature and critical code path of the MPC network is independently
audited.

| Report | Date | Target | Findings |
|---|---|---|---|
| [Chain Signatures](2025-03-06-trail-of-bits-chain-signatures.pdf) | 2025-03-06 | The MPC node and contract ([`near/mpc@51d5792`](https://github.com/near/mpc/tree/51d5792aafbc47322cf95b0f8e3d0e9da5cd3eec)) | 7 medium, 2 low, 6 informational |
| [PedPop+](2025-05-15-trail-of-bits-pedpop-plus.pdf) | 2025-05-15 | The distributed key generation protocol ([`near/mpc@e7777ee`](https://github.com/near/mpc/tree/e7777ee50f16837d899b5ce53c5709a1201b85bf), [`Near-One/cait-sith@5e0ce40`](https://github.com/Near-One/cait-sith/tree/5e0ce40a16dc3e0889277f66bb2a6400d6ef36a5)) | 1 medium, 1 low, 4 informational |
| [Confidential Key Derivation](2025-12-23-trail-of-bits-confidential-key-derivation.pdf) | 2025-12-23 | The BLS12-381 CKD scheme ([`near/threshold-signatures@e67c26c`](https://github.com/near/threshold-signatures/tree/e67c26c6dc33498b7e0545df929caa293d1cfc4e), [`near/mpc@2215b43`](https://github.com/near/mpc/tree/2215b43ddf6887b238779534d5ae5b3638b94e83)) | 2 high, 3 medium, 3 low, 7 informational |
| [Robust ECDSA](2026-02-10-trail-of-bits-robust-ecdsa.pdf) | 2026-02-10 | The robust threshold ECDSA scheme ([`near/threshold-signatures@657a2e4`](https://github.com/near/threshold-signatures/tree/657a2e4992ed9759ed5cd248e3004ff823a78783)) | 2 high, 1 medium, 1 low, 6 informational |
