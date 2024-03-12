// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

// ReciprocalPublic dimensions:
// Nd - count of private proles (size of committed value), Np - count of public poles (number system base).
// Nm = Nd, No = Np
// Nv = 1 + Nd
// G and HVec[0] will be used for the value commitment: VCom = value*G + blinding*HVec[0]
type ReciprocalPublic struct {
	G      *bn256.G1
	GVec   []*bn256.G1 // Nm
	HVec   []*bn256.G1 // Nv+9
	Nd, Np int

	// Vectors of points that will be used in WNLA protocol
	GVec_ []*bn256.G1 // 2^n - Nm
	HVec_ []*bn256.G1 // 2^n - (Nv+9)
}

type ReciprocalPrivate struct {
	X      *big.Int // Committed value
	M      []*big.Int
	Digits []*big.Int
	S      *big.Int // Blinding value (secret)
}

type ReciprocalProof struct {
	*ArithmeticCircuitProof
	V *bn256.G1
}

type PartitionType int

const (
	PartitionLO PartitionType = iota
	PartitionLL
	PartitionLR
	PartitionNO
)

type PartitionF = func(typ PartitionType, index int) *int

type ArithmeticCircuitPublic struct {
	Nm, Nl, Nv, Nw, No int // Nw = Nm + Nm + No (for L, R, O parts), Nl = Nv * K
	K                  int // Count of witness vectors v.
	G                  *bn256.G1
	GVec               []*bn256.G1 // Nm
	HVec               []*bn256.G1 // Nv+9

	Wm [][]*big.Int // Nm * Nw
	Wl [][]*big.Int // Nl * Nw

	Am []*big.Int // Nm
	Al []*big.Int // Nl

	Fl bool
	Fm bool

	F PartitionF

	// Vectors of points that will be used in WNLA protocol
	GVec_ []*bn256.G1 // 2^n - Nm
	HVec_ []*bn256.G1 // 2^n - (Nv+9)
}

type ArithmeticCircuitPrivate struct {
	V  [][]*big.Int // k*Nv
	Sv []*big.Int   // k
	Wl []*big.Int   // Nm
	Wr []*big.Int   // Nm
	Wo []*big.Int   // No
}

type ArithmeticCircuitProof struct {
	CL, CR, CO, CS *bn256.G1
	WNLA           *WeightNormLinearArgumentProof
}

// WeightNormLinearArgumentProof contains the proof of knowledge of vectors L, N for corresponding commitment C (is not
// included into the proof structure).
type WeightNormLinearArgumentProof struct {
	R, X []*bn256.G1
	L, N []*big.Int
}

// WeightNormLinearPublic contains the public values to be used in weight norm linear argument proof.
// The GVec and HVec sizes are recommended to be a powers of 2 and equal to the `n` and `l` private vector sizes.
type WeightNormLinearPublic struct {
	G          *bn256.G1
	GVec, HVec []*bn256.G1
	C          []*big.Int
	Ro, Mu     *big.Int // mu = ro^2
}

func NewWeightNormLinearPublic(lLen int, nLen int) *WeightNormLinearPublic {
	gvec := make([]*bn256.G1, nLen)
	for i := range gvec {
		gvec[i] = MustRandPoint()
	}

	hvec := make([]*bn256.G1, lLen)
	for i := range hvec {
		hvec[i] = MustRandPoint()
	}

	c := make([]*big.Int, lLen)
	for i := range c {
		c[i] = MustRandScalar()
	}

	ro := MustRandScalar()

	return &WeightNormLinearPublic{
		G:    MustRandPoint(),
		GVec: gvec,
		HVec: hvec,
		C:    c,
		Ro:   ro,
		Mu:   mul(ro, ro),
	}
}
