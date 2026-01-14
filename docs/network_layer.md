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

> In practice, we satisfy both requirements by running all protocols over a network where participants are connected via a TLS channel. This ensures both, authentication and confidentiality.

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

> To guarantee the security notions given by the Byzantine Reliable Broadcast, we assume that $3 \cdot \mathsf{MaxFaulty} +1 \leq N$. This bound originates from the classical Byzantine fault tolerance model \[[LSP82](https://lamport.azurewebsites.net/pubs/byz.pdf)\], which ensures both safety and liveness under such faults.

## Documentation Notation

In protocol specifications (particularly for ECDSA), we use the following symbols to describe actions:

| Symbol | Meaning | Description |
| :---: | :--- | :--- |
| $\star$ | **Send** | A participant sends a message to one or more others. |
| $\textcolor{red}{\star}$ | **Send Private** | A participant sends a private, encrypted message. |
| $\bullet$ | **Receive** | A participant waits to receive a message. |
| $\blacktriangle$ | **Assert** | A participant makes an assertion. The protocol aborts if it fails. |

## Byzantine Reliable Broadcast: Echo Broadcast

The Echo Broadcast (a.k.a. Authenticated Double-Echo Broadcast) protocol is a three-round protocol that allows all honest parties involved in a communication protocol to deliver the same message or all abort even if the protocol might contain faulty participants. The protocol admits one single sender (that is broadcasting message $m$) and multiple receivers (including the sender).

> Such a protocol assumes two properties:
>
> 1. The total number of faulty participants (nodes) cannot exceed one third of the maximum number of active participants, i.e., $3 \cdot \mathsf{MaxFaulty} +1 \leq N$
>
>2. The underlying peer-to-peer communication channel is authenticated.

The following figure is taken from \[[CGR](https://link.springer.com/book/10.1007/978-3-642-15260-3)\] book (section 3.11). The figure represents the three-round echo broadcast protocol (SEND, ECHO and READY).

![Broadcast Protocol](images/broadcast.png)

### Protocol Description

In the following description, if a participant $i$ receives a message from a participant $j$ at a specific round, then any additional message sent by $j$ for the same round is discarded by $i$. In other words, double voting is not taken into consideration.

#### Round 1: SEND Round

1. $\star$ The Sender sends $(\mathbf{SEND}, m)$ to every participant $i$ in the protocol

#### Round 2: ECHO Round

2. $\bullet$ Each participant $i$ waits to receive a message $(\mathbf{SEND},m_i)$ from the Sender.

3. $\star$ Each participant $i$ sends (echoes) to every other participant $j$ the received message $(\mathbf{ECHO}, m_i)$.

#### Round 3: READY Round

4. $\bullet$ Each participant $i$ waits to receive either a message $(\mathbf{ECHO}, m_i^j)$ - respectively $(\mathbf{READY}, m_i^j)$ - from participant $j$

5. Each participant $i$ stores $(\mathbf{ECHO}, m_i^j)$, resp. $(\mathbf{READY}, m_i^j)$.
If $(\mathbf{ECHO},m_i^j)$ - resp. $(\mathbf{READY}, m_i^j)$ - has not been previously stored, then store it along with a counter initialized to $1$. 
Otherwise, increase the corresponding counter by $1$.

6. $\star$ Once a counter for a message $(\mathbf{ECHO}, m)$ is greater than $~>\frac{N+\mathsf{MaxFaulty}}{2}$, send a $(\mathbf{READY}, m)$ to every participant $i$

7. $\star$ Once a counter for a message $(\mathbf{READY}, m)$ is greater than $~>\mathsf{MaxFaulty}$, send a $(\mathbf{READY}, m)$ to every participant $i$

8. $\star$ Once a counter for a message $(\mathbf{READY}, m)$ is greater than $~>2\cdot \mathsf{MaxFaulty}$, return (deliver) message $m$

$\quad$ *Note: the* $~\mathbf{READY}$ *message is sent once by each participant, thus either in step 6 or in step 7, but not in both.*

### Multi-Sender Protocol

In practice, cryptographic protocols typically involve multiple participants that execute the protocol symmetrically. In complex settings, all parties are required to synchronously broadcast cryptographic data. To achieve this, each participant must run several reliable echo broadcast protocols in parallel, with the constraint that each instance has a distinct sender.
To be able to allow this complexity, we implemented a multi-echo-broadcast protocol that does not make use of any parallelism. Our implementation intertwines multiple echo broadcast protocols (described above) and allow them to coexist by using session identifiers.

Each session deterministically selects a different sender. Every participant must attach the session identifier to any message it sends, and stored messages must also include this identifier.

From an implementation perspective, our `send_many` function is optimized to avoid delivering a message back to its sender. To accommodate scenarios in which a participant must effectively send a message to itself, we introduce the `is_simulated_vote` flag. This flag allows us to simulate a message that is both sent and received by the same participant, ensuring that the total number of message votes is counted correctly.
