# Bulletproofs++ implementation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Abstract

Present Go library contains the implementation of Bulletproofs++ weight norm linear argument protocol, arithmetic circuit
protocol and reciprocal range proof protocol.

Explore the [circuit_test.go](./circuit_test.go) to check the examples of circuit prove and verification.
It contains several circuits:

- Prove that we know such `x, y` that `x+y=r` and `x*y=z` for public `r, z`. This example encoded directly into the BP++
  circuits.
- Prove the range for 4-bits value: `x` is in `[0..2^n)` range (simple binary range proof).

Also, [reciprocal_test.go](./reciprocal_test.go) contains example of proving that value lies in [0, 2^n) range.

## Reciprocal range proofs

Check the following snippet as an example of usage of range proof protocol:

```go
package main

import (
  "github.com/cloudflare/bn256"
  "github.com/distributed-lab/bulletproofs"
  "math/big"
)

func main() {
  // The uint64 in 16-base system will be encoded in 8 digits.
  // The 16 base is selected as the most optimal base for this case.

  // Our private value is 0xab4f0540. Let's encode it as a list of digits:
  digits := []*big.Int{bint(0), bint(4), bint(5), bint(0), bint(15), bint(4), bint(11), bint(10)}
  
  x := big.NewInt(0xab4f0540)

  // Public poles multiplicities i-th element corresponds to the 'i-digit' multiplicity (the count of 'i-digit' in digits list) 
  m := []*big.Int{
    big.NewInt(2), // 0
    big.NewInt(0), // 1
    big.NewInt(0), // 2
    big.NewInt(0), // 3
    big.NewInt(2), // 4
    big.NewInt(1), // 5
    big.NewInt(0), // 6
    big.NewInt(0), // 7
    big.NewInt(0), // 8
    big.NewInt(0), // 9
    big.NewInt(1), // 10
    big.NewInt(1), // 11
    big.NewInt(0), // 12
    big.NewInt(0), // 13
    big.NewInt(0), // 14
    big.NewInt(1), // 15
  }

  Nd := 8  // digits size
  Np := 16 // base size

  var G *bn256.G1
  // Length of our base points vector should be a power ot 2 to be used in WNLA protocol. 
  // So cause the real HVec size in circuit is `2*Nd+Np+10` the nearest length is 64   
  var GVec []*bn256.G1 // len = 8
  var HVec []*bn256.G1 // len = 64

  public := &bulletproofs.ReciprocalPublic{
    G:     G,
    GVec:  GVec[:Nd],
    HVec:  HVec[:2*Nd+Np+10],
    Nd:    Nd,
    Np:    Np,
	
	// Remaining points that will be used in WNLA protocol
    GVec_: GVec[Nd:], 
    HVec_: HVec[2*Nd+Np+10:],
  }

  private := &ReciprocalPrivate{
    X:      x, // Committed value
    M:      m, // Corresponding multiplicities
    Digits: digits, // Corresponding digits
    S:     MustRandScalar(), // Blinding value (secret) used for committing value as: x*G + Sx*H
  }

  VCom := public.CommitValue(private.X, private.Sx) // Value commitment: x*G + Sx*H

  // Use NewKeccakFS or your own implementation for the Fiat-Shamir heuristics.
  proof := ProveRange(public, NewKeccakFS(), private)
  spew.Dump(proof)

  // If err is nil -> proof is valid.
  if err := VerifyRange(public, VCom, NewKeccakFS(), proof); err != nil {
    panic(err)
  }
}

```

## Weight norm linear argument (WNLA)

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