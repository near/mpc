This document specifies how the original ECDSA works.

# Preliminaries

Let $\mathbb{G}$ be a finite group generated with $G$ and of prime order $q$.

Let $H : \\{0, 1\\}^* \to \mathbb{F}_q$ denote a hash function used for hashing messages
for signatures.
Let $h : \mathbb{G} \to \mathbb{F}_q$ denote a different "hash function" used for converting points to scalars.
Commonly, this is done by "simply" taking the x coordinate of the affine
representation of a point.

# ECDSA Recap

ECDSA is a triplet of algorithm: key generation, signing, and verification.

Key generation takes nothing as input and a pair of secret key and public key:

$$
\begin{aligned}
&\underline{\texttt{Gen}}:\cr
&\ x \xleftarrow{\$} \mathbb{F}_q\cr
&\ X \gets x \cdot G\cr
&\ \texttt{return } (x, X)\cr
\end{aligned}
$$

Signing takes the secret key and a message $m \in \\{0, 1\\}^*$ as input and output the signature:

$$
\begin{aligned}
&\underline{\texttt{Sign}(x, m)}:\cr
&\ k \xleftarrow{\$} \mathbb{F}_q\cr
&\ R \gets k \cdot G\cr
&\ r \gets h(R)\cr
&\ \texttt{retry if } r = 0\cr
&\ s \gets k^{-1} (H(m) + rx)\cr
&\ \sigma \gets (R, s)\cr
&\ \texttt{return } \sigma\cr
\end{aligned}
$$

*Note that we slightly deviate from ANS X9.62 specifications by returning
the entire point* $R$ *instead of just* $r$*. This has absolutely no impact on the security
but makes it easier for downstream implementations to massage
the result signature into whatever format they need for compatability.*


Finally, the verification algorithm takes the public key the message and the signature and either accepts or rejects:

$$
\begin{aligned}
&\underline{\texttt{Verify}(X, m, \sigma):}\cr
&\ (R, s) \gets \sigma\cr
&\ r \gets h(R)\cr
&\ \texttt{assert } r \neq 0, s \neq 0\cr
&\ \hat{R} \gets \frac{H(m)}{s} \cdot G + \frac{r}{s} \cdot X\cr
&\ \texttt{assert } \hat{R} = R\cr
\end{aligned}
$$
