# C0 Contract Freeze

C0 freezes the migration boundary without changing the legacy algorithm. The
new Boolean facade owns the public contract, while the current implementation
still temporarily imports the root package until C2 moves LWE/GLWE/GGSW/KSK/PBS
into `src/core/*`.

The root experimental types and entry points are now marked deprecated. They
remain available only for compatibility and deterministic regression fixtures;
they are not production key-generation APIs. `Backend`, `SerializationKey`,
and structured backend errors are reserved by the facade so later phases do not
need to change public names while the implementation is migrated.
