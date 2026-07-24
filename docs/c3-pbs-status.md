# C3 PBS status

C3 now has the typed key-switching data flow and the complete two-point
Boolean LUT family:

- KSK rows are encrypted gadget powers and `KeySwitchKey::apply` performs
  signed decomposition without reading a secret key;
- Boolean `apply_lut` evaluates identity, NOT, false, and true tables through
  the existing gate facade;
- `PbsOrder` and `BooleanLut` establish the order/table contract for the
  upcoming standard BSK implementation.

The 110-bit and 128-bit records remain `reference_only`. `generate_keys` still
returns `UnsupportedBackend` for those records until standard Gaussian tables,
GLWE/GGSW encryption, blind rotation, and PBS-to-KS are connected. This is an
intentional hard gate: a deterministic or zero-noise substitute is not promoted
to the production API.
