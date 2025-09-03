# Robust ECDSA scheme

This is an amended version of the Robust ECDSA scheme of \[[DJNPO](https://eprint.iacr.org/2020/501.pdf)\].
The amendment can be found [here](https://docs.google.com/document/d/1FGxPg50lVzU3IRlUAlfinLWp6zh5uQqTJBvFXZj288c/edit?tab=t.0). It does away with several checks that the scheme requires to happen and thus dropping the security from active adversaries (under honest majority assumption) to honest-but-curious adversaries.

This implementation is meant to be integrated into a Trusted Execution Environment (TEE) which is meant prevent an adversary from deviating from the protocol. Additionally, the communication between the parties is assumed to be encrypted under secret keys integrated into the TEE.

## ATTENTION:
Some papers define the number of malicious parties (eg this exact paper) to be the same as the threshold.
Other papers seem to define the number of malicious parties to be threshold - 1.

The first case corresponds to robust ecdsa implementation (explicit condition on the threshold e.g. $n \geq 3 \cdot t + 1$).
The second case corresponds to the ot-based ecdsa implementation. (no explicit condition e.g.  $n \geq t$).

CARE TO UNIFY THE IMPLEMENTATION such as number of malicious parties = threshold. Discuss with the team such duality!
