# Benchmarking

Prior to this work, we had multiple implemented schemes that lacked practical performance comparison. We came up with two approaches that rely on Criterion to measure the computation time.
To provide fair measurements of the implemented schemes, we allow the comparison of schemes with similar functionalities under the same invariant: the security level, a.k.a. the **maximum number of malicious parties**. For the same maximum number of malicious parties, different schemes may require different numbers of active participants.

First, we cared about measuring how much time each scheme takes to complete end-to-end when being run with all the participants together. We call such measuring techniques the "naive technique". In fact, implementing this technique is fairly quick but the benchmarks are not 100% reliable. We discuss in the next section what this technique is about and why it is considered “naive”.

Next we brainstormed and implemented a more representative approach that utilizes a more "advanced technique" based on snapshotting the communication then replaying the protocol with a single participant using the snapshot. This technique allowed us to measure the basic computation time per participant and include network latency and the size of data sent over the wire.

Our benches have been executed on a laptop equipped with **AMD Ryzen 7 7730U with Radeon Graphics** and **16 GB RAM**. The number of iterations tested per experiment is at least **15 iterations**.

If interested only in the advanced benchmarking technique, please skip to section [Advanced Technique](#advanced-technique)

*Note: the triple generation for OT based ECDSA generates two triples, enough for the secure computation of one single presignature and thus one single signature.*

## Naive Technique

A quick solution to benchmark our schemes is to run the entire protocol for all the participants (side-by-side) and analyze the results.
We consider this benchmarking technique to be naive for several reasons:

1. It runs multiple participants in a sequential manner which combines with the quadratic/cubic nature of some of the protocols, preventing us from having a clear idea about each participant's computation time and representing network latency.

2. Combining running the participants sequential with having different signature schemes requiring different number of active participant (for the same maximum number of malicious parties) might create a bias in comparing the results across schemes.

3. A participant sending one message to all implies measuring the same send operation multiple time.

The table below shows running the criterion tests for the Robust ECDSA and OT-Based ECDSA schemes when fixing the maximum number of malicious parties to 6 participants.
One can see that the Robust ECDSA scheme seems much more performant than the OT-based ECDSA.

| Scheme | Parties | Two Triples Gen | Presign | Sign |
|:------:|:-------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 7 | 1.4237 s  | 1.4626 ms | 191.82 µs |
| **Robust ECDSA**   | 13 | N/A       | 66.060 ms | 278.13 µs |

| **Maximum number of malicious parties: 6** | **Network Latency: 0 ms** |
|---------------------------------------------|----------------------------|

*Note: These results reflect sequential protocol runs across all participants and should be interpreted with caution.*

## Advanced Technique

An accurate way to benchmark a protocol is by using the snap-then-simulate method: Instead of benchmarking the protocol run with all the participants included, we run the protocol including only two participants where only one  of them is real and the other is simulated. The real participant is the coordinator (where possible), and the simulated participant is the entire environment.
The real participant interacts with the simulation of the other parties.

More specifically, we first allowed the derandomization of the algorithms to benchmark. Then we implemented `run_protocol_and_take_snapshots` function which runs a specific protocol with all of it participants and stores in a dictionary the messages sent among the participants. Next we implemented the logic of what a simulator is and the function `run_simulated_protocol` allowing the simulator to reply in a dummy fashion to a real participant using the snapshot storage. It is essential to preserve the same order of messages sent during snapshot and simulation to be able to reproduce the same messages sent by the real participant twice (of course the same randomness is used twice for the real participant).
During the second (simulated) run, we benchmark the real participant's performance using Criterion. We also allowed adding latency discussed in section [Latency](#latency) and were able to measure the size of data received per participant during a protocol run.

### Why is this technique better than naive one?

1. Fair benchmarking of the different protocols: even when requiring more participants for one scheme, the benchmarking would focus on the actual performance of a single real participant instead of all participants.

2. Better representation of $O(n^2)$ communication protocol: simulating all-but-one participants would translate the protocol from $O(n^2)$ to $O(n)$ which makes the benchmarking way more focused on a single participant and avoiding the complexity of communication between the simulated participants

3. Better handling of the network latency: we can now add a wait at the reception of a message by the simulated participant. This can be tuned on demand reflecting variable network latency. This would reflect quite accurately the performance of different protocols that vary in the number of communication rounds.

4. Easy way to compute the size of data transmitted on the wire.

### Results & Analysis

In this section, we present a couple of results. The two following tables represent the time required by a single participant (coordinator if applicable) to complete a protocol. The numbers are, as expected, computed using the advanced benchmarking technique.

| Scheme | Parties | Two Triples Gen | Presign | Sign |
|:------:|:-------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 7 | 198.95 ms  | 206.52 µs | 111.76 µs |
| **Robust ECDSA**   | 13 | N/A       | 4.90 ms | 114.63 µs |
| **Ed25519 Frost**   | 7 | N/A       | N/A | 849.67 µs |
| **Ed25519 Frost with Presign**   | 7 | N/A       | 419.23 µs | 348.94 µs |

| **Maximum number of malicious parties: 6** | **Network Latency: 0 ms** |
|---------------------------------------------|----------------------------|

<br>

With a larger number of accepted malicious parties, the numbers are as follows:

| Scheme | Parties | Two Triples Gen | Presign | Sign |
|:------:|:-------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 16 | 544.94 ms  | 257.05 µs | 119.65 µs |
| **Robust ECDSA**   | 31 | N/A       | 24.56 ms | 129.45 µs |
| **Ed25519 Frost**   | 16 | N/A       | N/A | 1.7412 ms |
| **Ed25519 Frost with Presign**   | 16 | N/A       | 964.76 µs | 590.34 µs |

| **Maximum number of malicious parties: 15** | **Network Latency: 0 ms** |
|---------------------------------------------|----------------------------|

We notice two important results:

* For a maximum number of malicious parties 6, the time taken for **Two Triple Gen** and **Presign** in the naive benchmarking is roughly the time taken in the advanced setting multiplied by the number of active participants.

* The offline phase of Robust ECDSA is **40 times** faster than that of OT based ECDSA for a maximum number of malicious parties equals 6	and **22 times** faster for a maximum number of malicious parties equals 15. We estimate this difference to be due to the increasing number of necessary active participants in the Robust ECDSA setting.

#### Latency

Due to the fact that the computation time of both schemes is roughly small, adding latency to the schemes would absorb such speed into the results. The new results would thus depend mainly on the number of rounds each scheme takes to complete. Here is an estimation of the number of rounds needed per protocol run:

| Scheme | Two Triples Gen | Presign | Sign |
|:------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 8*  | 2 | 1 |
| **Robust ECDSA**   | N/A       | 3 | 1 |
| **Ed25519 Frost**   | N/A | N/A  | 3 |
| **Ed25519 Frost with Presign**   | N/A       | 1 | 1 |

| **Number of rounds** |
|---------------------------------------------|

*Note: The OT based ECDSA triple generation scheme requires more than 8 rounds of communication to complete. This number is an estimation that should give a good idea of the cost network latency on the benchmarking.*

<br>

Thus with network latency, the numbers are computed using the formula: **network_latency * protocol_number_rounds + raw_performance**. For example, we have the following results:

| Scheme | Parties | Two Triples Gen | Presign | Sign |
|:------:|:-------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 16 | 1.344 s  | 200.25 ms | 100.11 ms |
| **Robust ECDSA**   | 31 | N/A       | 324.56 ms | 100.12 ms |
| **Ed25519 Frost**  | 16 | N/A | N/A  | 301.74 ms |
| **Ed25519 Frost with Presign**   | 16 | N/A       | 100.96 ms  | 100.59 ms |

| **Maximum number of malicious parties: 15** | **Network Latency: 100 ms** |
|---------------------------------------------|----------------------------|

<br>

Notice that the Robust ECDSA offline phase is roughly **4.7 times** faster than the OT based ECDSA offline phase.
In fact, the higher the network latency is, the closer the performance of the Robust ECDSA offline phase would tend to **3.3 times** faster than the OT Based ECDSA offline phase. This is due to the fact that the OT Based ECDSA requires roughly **3.3 times** more rounds to complete.

#### Bandwidth

Sometimes, not being able to scale up in real systems is due to hitting the limits of the network bandwidth. We thus calculated the size of the data received by the real participant during a protocol run. Due to the hardness of deducing different rounds only based on the snapshot, we yet unable to compute exactly the size of received data per participant and per protocol round. Instead, we only compute the size of received data during an entire protocol run.

In the case where the protocol allows distinguishing between normal participants and a participant acting as a coordinator, we computed the size of data received by the coordinator. Naturally, a coordinator receives more data than the rest of the participants as it is the only party able to produce a signature. Our runs were stable in the size of the data sent, meaning, the variance of the computed number across the iterations was zero.

| Scheme | Parties | Two Triples Gen | Presign | Sign |
|:------:|:-------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 7 | 595260 Bytes  | 1416 Bytes | 557 Bytes |
| **Robust ECDSA**   | 13 | N/A       | 6387 Bytes | 1096 Bytes |
| **Ed25519 Frost**   | 7 | N/A       | N/A | 1510 Bytes |
| **Ed25519 Frost with Presign**   | 7 | N/A       | 918 Bytes | 609 Bytes |

| **Maximum number of malicious parties: 6** | **Network Latency: 0 ms** |
|---------------------------------------------|----------------------------|

*Note: The computed data size includes the cryptographic elements sent along with the metadata (e.g., receiver, session number etc…).*

<br>

| Scheme | Parties | Two Triples Gen | Presign | Sign |
|:------:|:-------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 16 | 2088966 Bytes  | 3485 Bytes | 1360 Bytes |
| **Robust ECDSA**   | 31 | N/A       | 15986 Bytes | 2752 Bytes |
| **Ed25519 Frost**   | 16 | N/A       | N/A | 3818 Bytes |
| **Ed25519 Frost with Presign**   | 7 | N/A       | 2274 Bytes |  |

| **Maximum number of malicious parties: 15** | **Network Latency: 0 ms** |
|---------------------------------------------|----------------------------|

*Note: The computed data size includes the cryptographic elements sent along with the metadata (e.g., receiver, session number etc…).*

<br>
