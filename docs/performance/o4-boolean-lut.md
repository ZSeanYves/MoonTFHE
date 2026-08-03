# O4 Boolean LUT lowering

The stable Boolean facade lowers gates to fixed programmable-bootstrap counts:

| Gate | PBS count | Encoding |
|---|---:|---|
| NOT | 0 | Linear Torus negation |
| NAND, AND, OR | 1 | `left + right - mu` negacyclic table |
| XOR, XNOR | 1 | `2 * (left + right) + mu` two-class phase table |
| MUX | 2 | Two half-amplitude AND tables plus linear recomposition |
| Constant unary LUT | 0 | Trivial public `+/-mu` ciphertext |

Here `mu = 2^29`. The XOR bias keeps both phase classes away from the
accumulator discontinuity. MUX refreshes each mutually exclusive branch at
`+/-mu/2`, then computes `2 * (selected_true + selected_false) + mu` without a
third PBS. Complete truth tables run on every backend; native standard circuit
evidence additionally exercises the same lowering with production noise.
