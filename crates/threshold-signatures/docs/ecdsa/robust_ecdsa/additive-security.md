# Security analysis: additive rerandomization variant

**Status: informal analysis (2026-07), not externally reviewed.** Complements the
[protocol specification](./signing.md#additive-rerandomization-variant); read that first.

## Claim structure

The argument is layered as in \[[GS22](https://eprint.iacr.org/2022/506)\]:

1. **MPC layer (this document).** The additive presign and sign protocols realize, with abort,
   a signing functionality that reveals nothing beyond $(R, \delta, s)$ per session — the
   interface of the attack game of \[[GS21](https://eprint.iacr.org/2021/1330.pdf)\] §8.4.
   The argument is information-theoretic, for $n = 2t+1$ and $t$ static corruptions.
2. **Signature layer.** \[[GS21](https://eprint.iacr.org/2021/1330.pdf)\] Theorems 5 and 6
   (elliptic-curve generic group model): ECDSA with additively rerandomized presignatures and
   additive key derivation is unforgeable, given that $\delta$ is unpredictable at signing-request time.
3. **Bridge.** \[[GS22](https://eprint.iacr.org/2022/506)\] §2.5: deriving
   $\delta \gets H(\mathsf{seed}, R, \epsilon, h)$ from a fresh public seed with an
   "entropy preserving" hash suffices for layer 2. Our HKDF instantiation
   (`RerandomizationArguments::derive_randomness`) takes the entropy argument as the seed and
   binds a superset of those inputs.

The MPC layer differs from the protocol proven in
\[[DJNPO20](https://eprint.iacr.org/2020/501)\] in exactly one way: $w = a \cdot k$ is never
opened and no authenticator $W = g^{ak}$ is computed; instead two values $(\hat{\mu}, \nu)$
are opened at signing time and checked only by final signature verification. Lemmas 1 and 2
below close exactly that gap. Everything else — the dealing round, $\mathsf{POWOPEN}$ for $R$
with its exponent-interpolation checks, the zero-sharing masks — is inherited unchanged from
\[[DJNPO20](https://eprint.iacr.org/2020/501)\]'s analysis (our presigning is a strict subset
of theirs).

## Setting and adversary model

Participants $P_1, \ldots, P_n$ with distinct nonzero identifiers, $n = 2t+1$ exactly, at most
$t$ statically corrupted (set $C$); $\lambda_i$ are the Lagrange coefficients at $0$ for the
full set. Following \[[DJNPO20](https://eprint.iacr.org/2020/501)\] (footnote 9) we assume
w.l.o.g. exactly $t$ corruptions, so the honest set $H$ has exactly $t+1$ members.

Assumed from outside this document:

* key generation produced a consistent degree-$t$ sharing $[x]$ and correct $X = x \cdot G$;
* all honest parties run rerandomization on identical
  $(Y, \epsilon, h, R, \mathcal{P}, \mathsf{entropy})$, presignatures are strictly one-time,
  and $h \neq 0$ (see [Security considerations](./signing.md#security-considerations));
* a presignature is never consumed by both this variant and the multiplicative one
  (see the `additive` module documentation).

Since there is no verifiable secret sharing, the adversary's degrees of freedom are:

* corrupt dealers may distribute **arbitrary values** (not on any polynomial) as their
  $a$-, $b$-, $d$-, $e$-contributions in round 1;
* corrupt parties may send **arbitrary pairs** $(\hat{\mu}_j, \nu_j)$ online;
* $k$-contributions to honest parties are forced degree-$t$ consistent by the retained
  $\mathsf{POWOPEN}$ checks: if the honest parties' summed $k$-shares do not lie on a degree-$t$
  polynomial, every honest party aborts
  (\[[DJNPO20](https://eprint.iacr.org/2020/501)\] §2.2). Hence when presigning completes,
  $R = k \cdot G$ is correct for the $k$ defined by the honest shares.

**Well-formedness w.l.o.g.** Because $|H| = t+1$, *any* values a corrupt dealer distributes to
the honest parties are consistent with some degree-$t$ polynomial ($t+1$ points), and any
$b$-, $d$-, $e$-contributions are consistent with some zero-constant degree-$2t$ polynomial
($t+1 \leq 2t$ points, for $t \geq 1$). Fix such completions; the corrupt parties' own reference
shares are then well-defined, and any discrepancy in what they actually send online folds into
the additive deviations $\Delta$ below. So w.l.o.g. all dealings are well-formed, and the only
adversarial freedom beyond dealing-value choice is the online messages.

## Lemma 1 — output correctness

*If the honest coordinator outputs a signature, it is the unique correct signature for
$(h, \epsilon)$ under the derived key $Y$, regardless of all deviations above.*

**Proof.** `Signature::verify` accepts $(\hat{R}, s)$ iff $s \neq 0$, $s$ is low-S, and
$x\big((h/s) G + (\rho/s) Y\big) = \rho$ where $\rho = x(\hat{R})$. For fixed
$(\rho, h, Y)$ this equation has exactly the two solutions $\pm s^\*$ where
$s^\* \cdot k' \equiv h + \rho(x+\epsilon)$ for the nonce $k'$ with $x(k'G) = \rho$, and the
low-S condition selects exactly one of them. The coordinator verifies against
$\rho = x(\hat{R})$ with $\hat{R} = R + \delta G = (k+\delta)G$, which is correct because $R$
came out of the checked $\mathsf{POWOPEN}$ and $\delta$ is a public local computation. Hence
the only value the coordinator can ever output is the low-S normalization of
$\big(h + \rho(x+\epsilon)\big) \cdot (k+\delta)^{-1}$. $\blacksquare$

Contrast with \[[DJNPO20](https://eprint.iacr.org/2020/501)\]: there, a corrupted opening of
$w$ would silently poison the *intermediate* value $[k^{-1}] = [a] \cdot w^{-1}$, which is why
the authenticator $W = g^{ak}$ exists. Here nothing derived from $\hat{\mu}$ or $\nu$ re-enters
secret computation — both openings are terminal — so signature verification is a complete
check, exactly the argument \[[DJNPO20](https://eprint.iacr.org/2020/501)\] makes for its own
terminal opening of $s$ ("*the only way the adversary can make the protocol succeed is by not
introducing any fault on $s$*"). What is lost relative to the original is only *when* faults
surface: a corrupted presignature is now detected at signing time (one wasted presignature and
a failed request) instead of during presigning.

## Lemma 2 — privacy

*The adversary's view of one session is perfectly simulatable given $(R, \delta, s^\*)$, even
when the protocol aborts.* (Learning $s^\*$ on abort matches the basic — unfair — protocol of
\[[DJNPO20](https://eprint.iacr.org/2020/501)\], where "the adversary gets to see the signature
and may then abort"; it is also what layer 2's attack game grants the adversary.)

The presign-phase view (round-1 shares, $R_i$ broadcasts) is simulated exactly as in
\[[DJNPO20](https://eprint.iacr.org/2020/501)\]: shares received by corrupt parties are
uniform, and the honest $R_i$ are patched by Lagrange interpolation in the exponent from $R$.
What remains is the signing round. The worst case is a **corrupt coordinator**, who sees every
honest pair $\big(\lambda_i \hat{\mu}_i,\ \lambda_i \nu_i\big)$; an honest coordinator reveals
strictly less.

**Step 1 — shares reduce to totals.** Honest $\hat{\mu}_i$ carry the mask $b_i$ and honest
$\nu_i$ carry the mask $\rho d_i + e_i$, with $(b), (d), (e)$ independent zero-constant
degree-$2t$ sharings. Conditioned on the corrupt parties' $t$ shares of each, the honest $t+1$
evaluations of each mask are uniform subject to a single linear relation (the degree-$2t$
interpolation through all $2t+1$ points has constant term zero). Hence the honest pairs are
jointly uniform subject only to their $\lambda$-weighted totals — the
$\mathsf{WMULOPEN}$ argument of \[[DJNPO20](https://eprint.iacr.org/2020/501)\], applied twice
with independent masks. The view therefore reduces to the two totals.

**Step 2 — the totals.** With well-formed dealings (w.l.o.g., above), write $a := f_A(0)$ where
$f_A$ sums all dealers' degree-$t$ $a$-polynomials. All degree-$2t$ products below interpolate
exactly at $2t+1$ points, and the zero-constant masks vanish from the totals, so with
$\Delta_\mu, \Delta_\nu$ denoting the corrupt parties' online deviations from their reference
values:

$$
\hat{\mu} = a(k+\delta) + \Delta_\mu,
\qquad
\nu = a\big(h + \rho(x+\epsilon)\big) + \Delta_\nu
     = s^\*(\hat{\mu} - \Delta_\mu) + \Delta_\nu .
$$

The deviations are computable from values the adversary holds (its own shares of
$a, k, b, d, e, x$ and the public $\delta, h, \rho$).

**Step 3 — simulation.** The honest dealers' contribution keeps $a$ uniform and unknown to the
adversary (its $t$ shares of a degree-$t$ polynomial leave the constant term free), and
$k + \delta \neq 0$ (else $\hat{R}$ is the identity and rerandomization already rejected). So
$a(k+\delta)$ is uniform, independent of everything else in the view — one fresh uniform mask
per session. The simulator: samples the honest-total for $\hat{\mu}$ uniformly, sets the
honest-total for $\nu$ by the identity above using $s^\*$ from the functionality and the
deviations it can compute (it knows all dealt values), and samples the individual honest pairs
uniformly subject to those totals (Step 1). Every quantity has the same distribution as in the
real execution, and the accept/abort outcome is a deterministic function of the resulting
totals, so it matches too. Sessions do not accumulate: each consumes a fresh presignature,
hence a fresh uniform $a$. $\blacksquare$

**Disagreement.** If honest parties disagree on $(h, \epsilon, \mathcal{P}, \mathsf{entropy})$,
they derive different $\delta$ (HKDF binds all of them), hence different $\rho$; the per-party
pads $\rho d_i + e_i$ then decorrelate and the opened totals are uniformly masked — the
protocol aborts without leakage. This is
\[[DJNPO20](https://eprint.iacr.org/2020/501)\]'s $[d] + m[e]$ message-binding argument, acting
through $\rho(\delta)$.

## Layers 2 and 3

Lemmas 1 and 2 say the protocol exposes exactly the interface of the rerandomized-presignature
attack game of \[[GS21](https://eprint.iacr.org/2021/1330.pdf)\] §8.4: presignature requests
reveal $R$; signing requests reveal $\delta$ and the correct signature (and nothing else, even
on abort). \[[GS21](https://eprint.iacr.org/2021/1330.pdf)\] Theorem 6 then bounds forgery
probability in the EC-GGM for additive key derivation, requiring only that $\delta$ is
unpredictable before the request is fixed (their Note 2: uniformity is not needed).
\[[GS22](https://eprint.iacr.org/2022/506)\] instantiates $\delta$ exactly as we do — a hash of
a fresh public seed, $R$, the tweak and the message hash — arguing an entropy-preserving hash
suffices. The freshness and unpredictability of the entropy argument is therefore
load-bearing and is an assumption on the caller (see `RerandomizationArguments`).

## Residual deviations from the cited proofs

* **Hash-derived $\delta$** rather than a random beacon: heuristic per
  \[[GS21](https://eprint.iacr.org/2021/1330.pdf)\] Note 2, argued sufficient by
  \[[GS22](https://eprint.iacr.org/2022/506)\] given a fresh seed.
* **Coordinator relay** instead of all-to-all opening: the corrupt-coordinator case analyzed in
  Lemma 2 is the maximal view, but the communication pattern itself is not in either paper.
* **Static corruptions**, as in \[[DJNPO20](https://eprint.iacr.org/2020/501)\].
* This write-up is an informal argument, not a machine-checked or externally reviewed proof.
