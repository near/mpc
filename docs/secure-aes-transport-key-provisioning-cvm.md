
# Secure AES Transport Key Provisioning for CVM Migration

## Reference

This document extends and refines the AES transport key mechanism defined in the official migration documentation:

https://github.com/near/mpc/blob/main/docs/migration-service.md

The full migration flow and the role of the AES key are defined there.  
This document focuses specifically on secure AES key provisioning in a CVM/TEE environment.

---

## Overview

This document describes a strongly authenticated and encrypted approach for provisioning the AES transport key (`transport_AES_key`) used during keyshare migration between CVM (Confidential VM) nodes and the migration service.

This ensures confidentiality against the host OS and strong operator authorization.

---

# Threat Model & Security Assumptions

## 1. Operator Environment

The operator has a secure environment in which they:

- Generate the AES transport key.
- Generate and store private keys (TLS key, AES_signing key).
- Perform contract registration / voting operations on-chain.

How the operator establishes and secures this environment is out of scope of this document.

---

## 2. Blockchain Trust Assumption

Our guarantees are as strong as the NEAR blockchain security model.

We assume:

- Forging or manipulating contract state is infeasible.
- On-chain key registration and authorization checks are trustworthy.
- Access-key validation reflects actual ownership.

All authorization decisions rely on the blockchain security assumption.

---

## 3. CVM / TEE Trust Model

- The CVM (TEE environment) is trusted.
- The host OS running the CVM is not trusted.
- The host OS may:
  - Read or modify environment variables.
  - Observe logs.
  - Intercept local traffic.
  - Attempt to substitute public keys.
- The host OS cannot:
  - Extract private keys from inside the CVM.
  - Break cryptography.
  - Forge attestation evidence.

---

# Purpose of the AES Transport Key

The AES transport key provides defense-in-depth protection during keyshare migration.

Without the AES key, a single point of failure during migration could expose keyshares.

With the AES key, an attacker must compromise:

1. The original protection mechanism (e.g., TLS, contract validation, etc.), and  
2. The AES transport key provisioning flow.

This increases the required attack surface from one failure to at least two independent failures.

---

## Example Threat Scenarios

### Example 1 — TLS Compromise

If TLS encryption is broken or misconfigured during key migration:

- Without AES transport encryption:
  - Keyshares could be exposed.
- With AES transport encryption:
  - Keyshares remain protected unless the AES key is also compromised.

---

### Example 2 — Operator Key Compromise + Malicious Migration Service

If the operator's Near account private key is leaked:

- An attacker could register a malicious migration service.
- Even with TEE protection, if the attacker controls the physical machine hosting the migration service, they may attempt to attack or exploit the TEE implementation.

With the AES transport key:

- The attacker must also obtain the AES key.
- This adds a second independent failure requirement.

---

### Example 3 — Contract Bug Allowing Malicious TLS Key Registration

If a bug in the migration contract allows arbitrary registration of a malicious migration service TLS key:

- An attacker could redirect migration traffic to a malicious endpoint.
- Even if TLS authentication appears valid, the endpoint could be attacker-controlled.

With AES transport encryption:

- The malicious service still cannot decrypt keyshares unless it also receives a valid operator-provisioned AES key.
- This prevents a single-layer compromise from exposing key material.

---

# Key Roles and Keys

## Operator Keys

The operator generates two asymmetric key pairs:

1. TLS key – used for mTLS communication.
2. AES_signing key – used exclusively to authorize AES key provisioning.

Both public keys are registered on-chain in the migration contract.

---

## CVM Node Keys

Each CVM node generates:

- AES_wrapping_keypair
  - Generated inside the CVM.
  - Private key never leaves the CVM.
  - Public key exposed via an attested local endpoint.

The same applies to the migration service.

---

# Provisioning Flow (Compact)

## Step 1 — Key Setup

- Operator generates:
  - TLS_keypair
  - AES_signing_keypair
- Operator registers public keys on-chain.
- Node and migration service each generate AES_wrapping_keypair inside CVM.

---

## Step 2 — Retrieve Wrapping Public Keys (Local + Attested)

Operator retrieves:

- node_AES_wrapping_pubkey
- migration_service_AES_wrapping_pubkey

via local attested endpoints.

The public keys are bound to CVM attestation evidence.

---

## Step 3 — Generate and Provision AES Transport Key (Local Only)

Operator:

1. Generates a 256-bit transport_AES_key.
2. Encrypts it to each target.
3. Signs each ciphertext.
4. Provisions the encrypted + signed blobs locally to the node and migration service.

Provisioning MUST be performed locally on the machine running the node / migration service.

This provides an additional guarantee that:

- The operator has control over the physical machine.
- The operator explicitly participates in enabling migration.
- Remote-only provisioning is not sufficient.

---

## Step 4 — Verification and Sealing

Each CVM:

- Verifies operator signature.
- Verifies signing key is registered on-chain.
- Decrypts transport_AES_key inside CVM.
- Seals the key for reuse.

Both sides now share the same operator-authorized AES transport key.

---

# Security Properties

## Confidentiality vs Host OS

- AES key is always encrypted to a CVM-held private key.
- The host OS cannot decrypt it.
- No plaintext AES key crosses the OS boundary.

## Strong Authorization

- Only a registered AES_signing_key can provision AES keys.
- Authorization is enforced via on-chain validation.

## Attestation Binding

- Wrapping keys are bound to CVM attestation.
- Prevents public key substitution by the host OS.

## Local Provisioning Guarantee

- AES provisioning must be executed locally.
- Ensures operator physical/logical control of the node host.
- Prevents purely remote activation of migration capability.

## Separation of Duties

- TLS key ≠ AES signing key.
- Limits blast radius if one key is compromised.

---

# Summary

This design provides:

- End-to-end encrypted AES key provisioning.
- On-chain authorized operator control.
- CVM-bound wrapping keys.
- Mandatory local operator involvement.
- Defense-in-depth against contract bugs, TLS compromise, and host-level attacks.

It transforms migration security from a single-point-of-failure model into a multi-layer failure requirement.
