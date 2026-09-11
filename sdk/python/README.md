# medicated-rsa (Python SDK)

Pure-standard-library Python implementation of Mediated RSA (mRSA): an
additive split of the RSA private exponent between a **member** and a
**mediator**. No third-party dependencies, no native code.

Requires Python 3.13+.

```python
from medicated_rsa import core

kp = core.generate_keypair(2048)
member, mediator = core.split_private_key(kp)  # d = d_M + d_Z mod λ(N)

em = core.encode_em(digest, (kp.n.bit_length() + 7) // 8)
sig = core.combine(
    core.partial_sign(member, em),
    core.partial_sign(mediator, em),
    kp.n,
)  # byte-for-byte a standard RSA signature

core.verify(core.PublicKey(kp.n, kp.e), em, sig)
```

Tests: `python3 -m unittest discover -s tests -v`

See the repository root README for the design rationale, the
cross-language error contract, and the shared test vector.
