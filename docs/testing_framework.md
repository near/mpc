# MPC System Test Framework

## Background

We currently have the following frameworks for e2e / system tests:
- pytest (which spins up a localnet, but will soon be deprecated due to halting support by nearcore)
- devnet (which is currently only used to deploy to testnet and lacks automated testing, c.f. https://github.com/near/mpc/issues/399)

Additionally, we have our localnet guide, which can spin up a localnet without depending on the soon to be deprecated pytest framework by nearcore.

Given that nearcore announced that their pytest library will soon be deprecated, we need to find an alternative on how to spin-up a localnet efficiently (c.f. #1825).
Additionally, we need to figure out a way to efficiently spin-up a localnet or testnest cluster that runs fully or partially in TEEs, because that is how we expect to run the network in production in the near future  uc.f. #1792).

In https://github.com/near/mpc/pull/1804, we introduced a bash-script to set-up a localnet, but we have reached consensus within the team, that it would be nice to have a higher-level programming language like rust or python for running more complicated setups and tests.

This document intents to achieve consensus on the rough design of a single test framework that could provide the desired functionalities:

- automated release testing on localnet and testnet
- gradual replacement for pytests
- automated localnet setup
- automated TEE setup


## Proposal

We have two choices:
- tear out the nearcore pytest part from our pytest library and replace it with our own logic for spawning localnets. This might be the easiest solution, with a few caveats:
 
- support localnet in devnet, which provides the following benefits:
    - localnet and devnet would be forced to share the same API, so any tests we would be writing for localnet could also be run on a cluster deployed to testnet
    - 

## Requirements on MPC testing

## Sources


---

KD: 
create an mpc cluster running on localnet.
specify, for each node, what code they should run off. Ideally by specifying commit, tag or docker images
specify different contract versions to run and update them


- https://nearone.slack.com/archives/C0912BTG51T/p1768921888210849?thread_ts=1768853976.744949&cid=C0912BTG51T

---
MB

Speaking of long term vision, I took some time yesterday to write down our system tests (existing + node compatibility) and what kind of tools/resources they need:
https://docs.nearone.org/doc/pytest-deprecation-qWpfDyTgVB
This is just an early draft, but afaik none of our pytests require fine-grained control over block production (e.g. fast-forward time or blocks) like we need in unit tests and some integration tests. From this perspective, I think we could run all of them against a single neard instance hosted in some existing environment. For the rest of the test, there is a mix between tests that need to control MPC nodes (start, stop, add new nodes, fault tolerance tests) and tests that are just verifying an existing system works as expected (add domain, produce signatures, web endpoint tests). The latter could also run in parallel against a localnet. For node compatibility tests, we could run the same test suite against a localnet with mixed versions of the nodes. The most complex tests are node migration tests imo. Contract migrations are also a bit special, but don't require fine-grained control over nodes.
Therefore, I think we should aim at two different setups:
Tests that require controlling MPC nodes and/or the contract -> pure Rust integration tests against a near blockchain configured in the environment. We'd likely want to do #1227 before this to get these tests to work as closely as possible to an end to end system, but I see no need to control MPC nodes as external processes as opposed to just spawning them in their own tokio tasks for this.
Tests that verify system behavior of an existing network -> Assumes an environment with a full MPC network set up, the test logic only concerns making the necessary requests.
I'll continue refine my thoughts in the project doc as well, but I think this is very relevant for #1784 (at least the long term solution for it). I'm not sure we have a good "quick implementation" for that one, so here it would be good to align on what we're targeting and break down the next steps to get us in that direction. We have the option to extend the pytest framework to support this right now but that wouldn't serve us well in the long run I believe.

https://nearone.slack.com/archives/C0912BTG51T/p1768983956932799?thread_ts=1768853976.744949&cid=C0912BTG51T
