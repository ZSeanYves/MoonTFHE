# C3 PBS status

C3 now has the typed key-switching data flow and a secret-free reference PBS
pipeline for the maintained core:

- KSK rows are encrypted gadget powers and `KeySwitchKey::apply` performs
  signed decomposition without reading a secret key;
- `BootstrapKey` accepts only encrypted GGSW controls and an encrypted KSK;
  it performs blind rotation, CMUX, sample extraction, and PBS->KS without
  retaining or reading a secret key;
- the reference backend evaluates identity and NOT LUTs with fixed-point
  Gaussian noise on toy parameters, and rejects the unsupported reverse order
  explicitly;
- Boolean `apply_lut` still evaluates the complete two-point family through the
  compatibility facade; the typed accumulator is the foundation for arbitrary
  programmable LUTs.

The 110-bit and 128-bit records remain `reference_only`. Stable
`generate_keys` still returns `UnsupportedBackend` for those records until the
standard Gaussian tables, production BSK generation, native FFT path, and
parameter estimator are connected. The typed PBS test uses only the sigma=3
fixture and toy dimensions; it is not a security claim and is not promoted to
the production API.
