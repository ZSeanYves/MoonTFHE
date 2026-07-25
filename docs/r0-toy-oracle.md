# R0 toy oracle

R0 freezes the reference Boolean pipeline before the standard-parameter and
Fourier storage changes. The oracle covers Torus32 encoding, modulus switching,
signed gadget decomposition, the GGSW row convention, negacyclic sample
extraction, and both supported PBS orders.

The `src/core/pbs/oracle_wbtest.mbt` contract executes 10,000 deterministic
toy circuit steps after checking both external key domains. Existing core tests
retain a non-zero-noise PBS case. These tests establish implementation
consistency only: the toy record has no security level and must never be exposed
through production key generation.

The committed scalar fixture records the pinned tfhe-rs source commit and the
cross-implementation conventions that later differential tools must preserve.
It is deliberately not described as ciphertext interoperability data.
