# Bulletproofs++ implementation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Example

Explore the [circuit_test.go](./circuit_test.go) to check the examples of circuit prove and verification.
It contains several circuits:

- Prove that we know such `p` and `q` that `p*q=r` for some public `r`. This example is presented in the BP form and
  translated into the BP++ form according to our paper.
- Prove that we know such `x, y` that `x+y=r` and `x*y=z` for public `r, z`. This example encoded directly into the BP++
  circuits.
- Prove the range for 4-bits value: `x` is in `[0..2^n)` range.

## Weight norm linear argument

The [wnla.go](./wnla.go) contains the implementation of **weight norm linear argument** protocol. This is a fundamental
basis for arithmetic circuit protocol. It uses the Fiat-Shamir heuristics from [fs.go](./fs.go) to generate challenges
and make protocol non-interactive.

Check the following snippet with an example of WNLA usage:

```go
package main

import (
	"github.com/distributed-lab/bulletproofs"
	"math/big"
)

func main() {
	public := bulletproofs.NewWeightNormLinearPublic(4, 2)

	// Private
	l := []*big.Int{big.NewInt(4), big.NewInt(5), big.NewInt(10), big.NewInt(1)}
	n := []*big.Int{big.NewInt(2), big.NewInt(1)}

	proof := bulletproofs.ProveWNLA(public, public.Commit(l, n), bulletproofs.NewKeccakFS(), l, n)
	if err := bulletproofs.VerifyWNLA(public, proof, public.Commit(l, n), bulletproofs.NewKeccakFS()); err != nil {
		panic(err)
	}
}

```

## Arithmetic circuit

The [circuit.go](./circuit.go) contains the implementation of BP++ arithmetic circuit protocol.
It runs the WNLA protocol as the final stages of proving/verification. Uses the Fiat-Shamir heuristics
from [fs.go](./fs.go) to generate challenges
and make protocol non-interactive.

Check the following snippet with an example of arithmetic circuit protocol usage:

```go
package main

import (
	"github.com/cloudflare/bn256"
	"github.com/distributed-lab/bulletproofs"
)

func main() {
	public := &bulletproofs.ArithmeticCircuitPublic{
		Nm,
		Nl, // Nl = Nv * K
		Nv, // Size on any v witness vector
		Nw, // Nw = Nm + Nm + No
		No,
		K, // count of v witnesses vectors
		G,

		// points that will be used directly in circuit protocol
		GVec[:Nm],   // Nm
		HVec[:Nv+9], // Nv+9

		// Circuit definition 
		Wm, // Nm * Nw
		Wl, // Nl * Nw
		Am, // Nm
		Al, // Nl
		Fl,
		Fm,

		// Partition function
		F: func(typ bulletproofs.PartitionType, index int) *int {
			// define
			return nil
		},

		// points that will be used in WNLA protocol to make vectors 2^n len
		HVec[Nv+9:], // 2^x - (Nv+9) dimension
		GVec[Nm:],   // 2^y - Nm dimension
	}

	private := &bulletproofs.ArithmeticCircuitPrivate{
		V,  // witness vectors v, dimension k*Nv
		Sv, // witness blinding values, dimension k
		Wl, // Nm
		Wr, // Nm
		Wo, // No
	}

	// Commitments to the v witness vectors
	V := make([]*bn256.G1, public.K)
	for i := range V {
		V[i] = public.CommitCircuit(private.V[i], private.Sv[i], public.G, public.HVec)
	}

	proof := bulletproofs.ProveCircuit(public, bulletproofs.NewKeccakFS(), private)

	if err := bulletproofs.VerifyCircuit(public, V, bulletproofs.NewKeccakFS(), proof); err != nil {
		panic(err)
	}
}
```