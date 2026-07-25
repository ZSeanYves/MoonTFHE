# C3 PBS status

C3 now has the typed key-switching data flow and a secret-free reference PBS
pipeline for the maintained core:

- KSK rows are encrypted gadget powers and `KeySwitchKey::apply` performs
  signed decomposition without reading a secret key;
- `BootstrapKey` accepts only encrypted GGSW controls and an encrypted KSK;
  it performs blind rotation, CMUX, sample extraction, and PBS->KS without
  retaining or reading a secret key;
- the reference backend evaluates identity, NOT and arbitrary anti-periodic
  Torus tables on toy parameters, and rejects the unsupported reverse order
  explicitly;
- the stable Boolean facade directly owns typed core entities and evaluates the
  complete two-point family without importing a legacy root package.

The 110-bit and 128-bit records remain `reference_only`. Stable
`generate_keys` still returns `UnsupportedBackend` for those records until the
production BSK generation, Fourier conversion, and verified parameter estimator
are connected. Standard CDT tables now exist, but the typed PBS contract tests
still use toy dimensions and test-only distributions; they are not a security
claim and are not promoted to the production API.
