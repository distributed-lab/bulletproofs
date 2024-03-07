// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"math/big"
	"testing"
)

func TestReciprocalRangeProofUInt64(t *testing.T) {
	// uint64 in 16-base system will be encoded in 8 digits

	// 0x0450f4ba
	digits := []*big.Int{bint(0), bint(4), bint(5), bint(0), bint(15), bint(4), bint(11), bint(10)}

	// Public poles multiplicities i-th element corresponds to the 'i-digit' multiplicity
	m := []*big.Int{
		bint(2), // 0
		bint(0), // 1
		bint(0), // 2
		bint(0), // 3
		bint(2), // 4
		bint(1), // 5
		bint(0), // 6
		bint(0), // 7
		bint(0), // 8
		bint(0), // 9
		bint(1), // 10
		bint(1), // 11
		bint(0), // 12
		bint(0), // 13
		bint(0), // 14
		bint(1), // 15
	}

	Nd := 8  // digits size
	Np := 16 // base size

	wnlaPublic := NewWeightNormLinearPublic(64, 8)

	public := &ReciprocalPublic{
		G:     wnlaPublic.G,
		GVec:  wnlaPublic.GVec[:Nd],
		HVec:  wnlaPublic.HVec[:2*Nd+Np+9],
		Nd:    Nd,
		Np:    Np,
		GVec_: wnlaPublic.GVec[Nd:],
		HVec_: wnlaPublic.HVec[2*Nd+Np+9:],
	}

	private := &ReciprocalPrivate{
		V:  append(digits, m...),
		Sv: MustRandScalar(),
	}

	V := public.CommitCircuit(private.V, private.Sv)

	proof := ProveRange(public, V, NewKeccakFS(), private)

	if err := VerifyRange(public, V, NewKeccakFS(), proof); err != nil {
		panic(err)
	}
}
