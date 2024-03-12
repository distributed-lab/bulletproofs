// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"testing"
)

func TestReciprocalRangeProofUInt64(t *testing.T) {
	// uint64 in 16-base system will be encoded in 16 digits

	x := uint64(0xab4f0540ab4f0540)
	X := new(big.Int).SetUint64(x)

	digits := UInt64Hex(x) // 16

	// Public poles multiplicities i-th element corresponds to the 'i-digit' multiplicity
	m := HexMapping(digits) // 16

	Nd := 16 // digits size
	Np := 16 // base size

	wnlaPublic := NewWeightNormLinearPublic(32, 16)

	public := &ReciprocalPublic{
		G:     wnlaPublic.G,
		GVec:  wnlaPublic.GVec[:Nd],
		HVec:  wnlaPublic.HVec[:Nd+1+9],
		Nd:    Nd,
		Np:    Np,
		GVec_: wnlaPublic.GVec[Nd:],
		HVec_: wnlaPublic.HVec[Nd+1+9:],
	}

	private := &ReciprocalPrivate{
		X:      X,
		M:      m,
		Digits: digits,
		S:      MustRandScalar(),
	}

	VCom := public.CommitValue(private.X, private.S)

	proof := ProveRange(public, NewKeccakFS(), private)
	spew.Dump(proof)

	if err := VerifyRange(public, VCom, NewKeccakFS(), proof); err != nil {
		panic(err)
	}
}
