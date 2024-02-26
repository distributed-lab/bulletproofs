// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"testing"
)

func TestArithmeticCircuit(t *testing.T) {
	// Scheme to proof that we know such p, q that:
	// pq = r
	// for some public r.

	// r = 15, p = 3, q = 5

	p := bint(3)
	q := bint(5)

	// Challenge x = 10

	// Wl*w = M(Wl*al + Wr*ar + Wo*ao)
	// fl*wv+al = v+al = -Wl*w = -M(Wl*al + Wr*ar + Wo*ao) = -M(Wv*v+c)
	// v+al = -M*(Wv*v) - M*c
	// if M such that -M(Wv*v) = v then al = -M*c

	// Corresponding matrix M such that -M(Wv*v) = v
	m := []*big.Int{frac(3, 530), frac(5, 530)}

	al := vectorMulOnScalar(m, bint(-15*1000)) // -m * c = -m * (r * z^3)

	// Wlw = M(Wl*al + Wr*ar + Wo*ao)
	// Wl*al + Wr*ar + Wo*ao = -30 - 500 + 15000 = 14470
	// M(Wl*al + Wr*ar + Wo*ao) = [1447/101, 14470/101]

	Wlw := vectorMulOnScalar(m, bint(14470)) // 2

	// left inverse w = [3/259, 5/259, 15/259]
	wInv := []*big.Int{frac(3, 259), frac(5, 259), frac(15, 259)} // 3

	var Wl [][]*big.Int = make([][]*big.Int, 2)
	for i := range Wl {
		Wl[i] = make([]*big.Int, 3)

		for j := range Wl[i] {
			Wl[i][j] = mul(Wlw[i], wInv[j])
		}
	}

	Wm := [][]*big.Int{
		{bint(0), bint(0), bint(1)},
	} // [0, 0, 1]

	wnlaPublic := NewWeightNormLinearPublic(16, 1)

	public := &ArithmeticCircuitPublic{
		Nm:   1,
		Nl:   2,
		Nv:   2,
		Nw:   3,
		No:   1,
		K:    1,
		G:    wnlaPublic.G,
		GVec: wnlaPublic.GVec[:1],
		HVec: wnlaPublic.HVec[:11],
		Wm:   Wm,
		Wl:   Wl,
		Am:   zeroVector(1),
		Al:   al,
		Fl:   true,
		Fm:   false,
		F: func(typ PartitionType, index int) *int {
			if typ == PartitionNO { // map all to no
				return &index
			}

			return nil
		},
		HVec_: wnlaPublic.HVec[11:],
		GVec_: wnlaPublic.GVec[1:],
	}

	private := &ArithmeticCircuitPrivate{
		V:  [][]*big.Int{{p, q}},
		Sv: []*big.Int{MustRandScalar()},
		Wl: []*big.Int{p},
		Wr: []*big.Int{q},
		Wo: []*big.Int{mul(p, q)},
	}

	V := make([]*bn256.G1, public.K)
	for i := range V {
		V[i] = CommitCircuit(private.V[i], private.Sv[i], public.G, public.HVec)
	}

	proof := ProveCircuit(public, NewKeccakFS(), private)
	spew.Dump(proof)

	if err := VerifyCircuit(public, V, NewKeccakFS(), proof); err != nil {
		panic(err)
	}
}

func frac(a, b int) *big.Int {
	return mul(bint(a), inv(bint(b)))
}
