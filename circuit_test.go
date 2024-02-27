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
			if typ == PartitionLL { // map all to ll
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

func TestArithmeticCircuitBinaryRangeProof(t *testing.T) {
	value := []*big.Int{bint(0), bint(1), bint(1), bint(0)} // bin(0110) = dec(6)
	// We have prove that value < 2^n - 1
	// Proving of the bits count is automatic (public parameters dimension will not allow to verify prove for bigger value)
	// Then we should prove that every value is a bit
	// To do that have to prove that every value[i] * (value[i] - 1) = 0

	// For the 4-bit value we will have te following constraints:
	// value0*value0 = a0
	// a0 - value0 = 0

	// value1*value1 = a1
	// a1 - value1 = 0

	// value2*value2 = a2
	// a2 - x2 = 0

	// value3*value3 = a3
	// a3 - value3 = 0

	Nm := 4
	No := 4
	Nv := 2
	K := 4

	Nl := Nv * K       // 8
	Nw := Nm + Nm + No // 12

	a := hadamardMul(value, value) // a[i] = value[i] * value[i]

	v := [][]*big.Int{
		{value[0], a[0]},
		{value[1], a[1]},
		{value[2], a[2]},
		{value[3], a[3]},
	}

	wl := value
	wr := value
	wo := a

	w := append(wl, wr...)
	w = append(w, wo...) // w = wl||wl||wo

	wv := make([]*big.Int, 0, Nw)
	for i := range v {
		wv = append(wv, v[i]...)
	}

	Wm := [][]*big.Int{
		{bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(1), bint(0), bint(0), bint(0)},
		{bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(1), bint(0), bint(0)},
		{bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(1), bint(0)},
		{bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(1)},
	} // Nm*Nw = 4 * 12

	Am := zeroVector(Nm) // Nm

	Wl := [][]*big.Int{
		{bint(-1), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0)},
		{bint(-1), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0)},
		{bint(0), bint(-1), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0)},
		{bint(0), bint(-1), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0)},
		{bint(0), bint(0), bint(-1), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0)},
		{bint(0), bint(0), bint(-1), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0)},
		{bint(0), bint(0), bint(0), bint(-1), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0)},
		{bint(0), bint(0), bint(0), bint(-1), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0), bint(0)},
	} // Nl*Nw  = 8 * 12

	Al := zeroVector(Nl)

	fmt.Println("Circuit check:", matrixMulOnVector(w, Wm), "=", hadamardMul(wl, wr))
	fmt.Println("Circuit check:", vectorAdd(vectorAdd(matrixMulOnVector(w, Wl), wv), Al), "= 0")

	wnla := NewWeightNormLinearPublic(16, Nm)

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
			if typ == PartitionNO { // map all to no
				return &index
			}

			return nil
		},

		GVec_: wnla.GVec[Nm:],
		HVec_: wnla.HVec[9+Nv:],
	}

	private := &ArithmeticCircuitPrivate{
		V:  v,
		Sv: []*big.Int{MustRandScalar(), MustRandScalar(), MustRandScalar(), MustRandScalar()},
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

func matrixMulOnVector(a []*big.Int, m [][]*big.Int) []*big.Int {
	var res []*big.Int

	for i := 0; i < len(m); i++ {
		res = append(res, vectorMul(a, m[i]))
	}

	return res
}

func hadamardMul(a, b []*big.Int) []*big.Int {
	res := make([]*big.Int, len(a))
	for i := range res {
		res[i] = mul(a[i], b[i])
	}

	return res
}

func frac(a, b int) *big.Int {
	return mul(bint(a), inv(bint(b)))
}
