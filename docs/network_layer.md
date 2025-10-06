# Protocol Communication Layer

This document outlines the communication layer for our multi-party computation (MPC) protocols, covering its assumptions, functions, and documentation notation.

## Core Assumptions

Our protocols operate on two fundamental assumptions about the network channels:

- **Authenticated Channels:** All messages are sent over authenticated channels. Senders' identities are always verifiable.
- **Confidentiality for Private Messages:** Channels used for private messages (`send_private`) must be encrypted.

<details>
  <summary>Practical Implementation</summary>
  In practice, we satisfy both requirements by running all protocols over a network where participants are connected via a TLS channel. This ensures both, authentication and confidentiality.
</details>

## Communication Primitives

The protocol implementation provides several communication primitives:

- **`send_many`**: Sends a message to participants except the sender itself. This is a peer-to-peer sending with no security guarantees used by one sender in destination to multiple receiver.

- **`send_private`**: Sends a message to a single, specific participant. The underlying channel is assumed to be confidential.

- **Byzantine Reliable Broadcast (`echo_broadcast`)**: A complex protocol that ensures all honest participants agree on the same message, even in the presence of Byzantine faults. The protocol guarantees:

  - **Validity**: If a correct process `p` broadcasts `a` message `m`, then `p` eventually delivers `m`.
  
  - **No duplication**: No message is delivered more than once.
  
  - **No creation**: If a process delivers a message `m` with sender `s`, then m was previously broadcast by process `s`.

  - **Agreement**: If a message `m` is delivered by some correct process, then `m` is eventually delivered by every correct process.

  - **Totality**: If some message is delivered by any correct process, then every correct process eventually delivers some message.

> To guarantee the security notions given by the Byzantine Reliable Broadcast, we assume that `N >= 3f +1`. This bound originates from the classical Byzantine fault tolerance model [LSP82](https://lamport.azurewebsites.net/pubs/byz.pdf), which ensures both safety and liveness under such faults.

## Documentation Notation
In protocol specifications (particularly for ECDSA), we use the following symbols to describe actions:

| Symbol | Meaning | Description |
| :---: | :--- | :--- |
| $\star$ | **Send** | A participant sends a message to one or more others. |
| $\textcolor{red}{\star}$ | **Send Private** | A participant sends a private, encrypted message. |
| $\bullet$ | **Receive** | A participant waits to receive a message. |
| $\blacktriangle$ | **Assert** | A participant makes an assertion. The protocol aborts if it fails. |
