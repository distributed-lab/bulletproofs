# Bulletproofs++ implementation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Weight norm linear argument

The [wnla.go](./wnla.go) contains the implementation of **weight norm linear argument** protocol. This is a fundamental
basis for arithmetic circuit protocol. It uses the Fiat-Shamir heuristics from [fs.go](./fs.go) to generate challenges
and make protocol non-interactive.

Check the following snippet with an example of WNLA usage:

```go
package main

import "math/big"

func main() {
	public := NewWeightNormLinearPublic(4, 2)

	// Private
	l := []*big.Int{big.NewInt(4), big.NewInt(5), big.NewInt(10), big.NewInt(1)}
	n := []*big.Int{big.NewInt(2), big.NewInt(1)}

	proof := ProveWNLA(public, public.Commit(l, n), NewKeccakFS(), l, n)
	if err := VerifyWNLA(public, proof, public.Commit(l, n), NewKeccakFS()); err != nil {
		panic(err)

	}
}

```