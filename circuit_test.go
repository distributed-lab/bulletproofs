// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"fmt"
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

	/*
		// In the BP circuit representation:
		al = [p]
		ar = [q]
		ao = [p * q]
		v = [p, q]

		Wl = [x]
		Wr = [x^2]
		Wo = [x^3]
		Wv = [x, x^2]
		c = r * x^3

		This satisfies
		(1) Wl*al + Wr*ar + Wo*ao = Wv*v + c
		(2) al ◦ ar = ao
	*/

	// Using M = [−p, −q] * (zp + z2q)^−1 (check out our paper why), we can calculate the BP++ representation:
	// Wl*w = M(Wl*al + Wr*ar + Wo*ao)
	// al = -m * c

	// Matrix M such that -M(Wv*v) = v
	m := vectorMulOnScalar([]*big.Int{bint(-3), bint(-5)}, inv(bint(30+500)))

	al := vectorMulOnScalar(m, bint(-15*1000)) // -m * c = -m * (r * z^3)

	// Wl*al + Wr*ar + Wo*ao = 30 + 500 + 15000 = 15530
	Wlw := vectorMulOnScalar(m, bint(15530))

	// w = [3, 5, 15] = al|ar|ao
	// left inverse w = [3/259, 5/259, 15/259]
	wInv := []*big.Int{frac(3, 259), frac(5, 259), frac(15, 259)}

	// Wl = Wl*w*w^-1
	var Wl [][]*big.Int = make([][]*big.Int, 2)
	for i := range Wl {
		Wl[i] = make([]*big.Int, 3)

		for j := range Wl[i] {
			Wl[i][j] = mul(Wlw[i], wInv[j])
		}
	}

	// Wm*w = wl*wr = al*ar
	// => Wm = [0, 0, 1]
	Wm := [][]*big.Int{
		{bint(0), bint(0), bint(1)},
	}

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
		V[i] = public.CommitCircuit(private.V[i], private.Sv[i])
	}

	proof := ProveCircuit(public, NewKeccakFS(), private)
	spew.Dump(proof)

	if err := VerifyCircuit(public, V, NewKeccakFS(), proof); err != nil {
		panic(err)
	}
}

func TestArithmeticCircuit2(t *testing.T) {
	// Test the knowledge of x, y for public z, r, such:
	// x + y = r
	// x * y = z

	x := bint(3)
	y := bint(5)

	r := bint(8)
	z := bint(15)

	wl := []*big.Int{x}
	wr := []*big.Int{y}
	wo := []*big.Int{z, r}

	wv := []*big.Int{x, y}
	w := []*big.Int{x, y, z, r} // w = wl||wr||wo

	Nm := 1
	No := 2
	Nv := 2
	K := 1

	Nl := Nv * K       // 2
	Nw := Nm + Nm + No // 4

	Wm := [][]*big.Int{{bint(0), bint(0), bint(1), bint(0)}} // Nm*Nw
	Am := []*big.Int{bint(0)}                                // Nm

	Wl := [][]*big.Int{
		{bint(0), bint(1), bint(0), bint(0)},
		{bint(1), bint(0), bint(0), bint(-1)},
	} // Nl*Nw

	Al := []*big.Int{minus(r), bint(0)} // Nl

	fmt.Println("Circuit check:", vectorMul(Wm[0], w), "=", vectorMul(wl, wr))
	fmt.Println("Circuit check:", vectorAdd(vectorAdd([]*big.Int{vectorMul(Wl[0], w), vectorMul(Wl[1], w)}, wv), Al), "= 0")

	wnla := NewWeightNormLinearPublic(16, 1)

	public := &ArithmeticCircuitPublic{
		Nm: Nm,
		Nl: Nl,
		Nv: Nv,
		Nw: Nw,
		No: No,
		K:  K,

		G:    wnla.G,
		GVec: wnla.GVec[:Nm],
		HVec: wnla.HVec[:9+Nv],

		Wm: Wm,
		Wl: Wl,
		Am: Am,
		Al: Al,
		Fl: true,
		Fm: false,

		F: func(typ PartitionType, index int) *int {
			if typ == PartitionLL { // map all to no
				return &index
			}

			return nil
		},

		GVec_: wnla.GVec[Nm:],
		HVec_: wnla.HVec[9+Nv:],
	}

	private := &ArithmeticCircuitPrivate{
		V:  [][]*big.Int{wv},
		Sv: []*big.Int{MustRandScalar()},
		Wl: wl,
		Wr: wr,
		Wo: wo,
	}

	V := make([]*bn256.G1, public.K)
	for i := range V {
		V[i] = public.CommitCircuit(private.V[i], private.Sv[i])
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
