# Proactive Security

## Goal

The master secret key lives for years, and over that time an attacker may
compromise $\mathsf{threshold}$ participants one at a time, through software
exploits, stolen backups or insiders, without ever controlling that many at
once. Proactive security protects the key against such an attacker by bounding
what it may hold per period instead of over the key's whole lifetime.

Time is divided into *epochs*. Every reshare and every refresh (see
[DKG](./dkg.md)) starts a new one, in which a fixed set of participants holds
shares of the master secret key under a fixed $\mathsf{threshold}$. Shares of
different epochs do not combine. The adversary is *mobile*: it can move from one
participant to another, and a participant it loses control of, for example after
a reinstall that replaces its authentication key, is no longer corrupted. The
master secret key stays hidden as long as, in every epoch, fewer than that
epoch's $\mathsf{threshold}$ participants are corrupted. A participant corrupted
during a reshare or refresh counts as corrupted in both the old and the new
epoch, since it then holds shares of both.

## Refreshing the shares

A [refresh](./dkg.md#key-refresh) gives every participant a new share of the
same master secret key. Each participant re-shares its old share with fresh
randomness, and the new shares form a fresh random sharing of the key, unrelated
to the old one except through the key itself. The master public key stays the
same, so users see no change. A reshare has the same effect, and can also change
the participants and the threshold.

For example, with a threshold of 3, an adversary that corrupts two participants
in one epoch, loses them before the refresh, and corrupts a third in the next
learns nothing about the key. Without the refresh in between, the same three
shares reconstruct it.

Running a refresh periodically thus bounds the time the adversary has to corrupt
$\mathsf{threshold}$ participants. A shorter period shrinks that window but
means more frequent refreshes, each costing a run of the DKG protocol and the
regeneration of the triples it requires erasing.

## Erasure requirement

These guarantees hold only if every participant erases:

* its keyshare of the old epoch, once the new epoch is in use;
* its [triple](./ecdsa/ot_based_ecdsa/triples.md) shares: unused ones at the
  epoch change, used ones once their signing run ends.

Without erasure, $\mathsf{threshold}$ shares of any single past epoch, collected
at any time, reconstruct the master secret key. Triples do not depend on the
key, but [signing](./ecdsa/ot_based_ecdsa/signing.md) reveals $k + a$ and
$x + b$, so shares of a triple that outlive its epoch add up across epochs just
as keyshares do.

Keyshare backups count as shares of their epoch, so they must be erased too.
