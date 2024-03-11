// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

func (p *ReciprocalPublic) CommitValue(v *big.Int, s *big.Int) *bn256.G1 {
	res := new(bn256.G1).ScalarMult(p.G, v)
	res.Add(res, new(bn256.G1).ScalarMult(p.HVec[0], s))
	return res
}

func (p *ReciprocalPublic) CommitWitness(d, m []*big.Int, s *big.Int) *bn256.G1 {
	res := new(bn256.G1).ScalarMult(p.HVec[0], s)
	res.Add(res, vectorPointScalarMul(p.HVec[9:], append(d, m...)))
	return res
}

func (p *ReciprocalPublic) CommitPoles(r []*big.Int, s *big.Int) *bn256.G1 {
	res := new(bn256.G1).ScalarMult(p.HVec[0], s)
	res.Add(res, vectorPointScalarMul(p.HVec[9+p.Nd+p.Np:], r))
	return res
}

// ProveRange generates zero knowledge proof that corresponding to the committed digits vector value lies in [0, 2^n) range.
// Use empty FiatShamirEngine for call.
func ProveRange(public *ReciprocalPublic, fs FiatShamirEngine, private *ReciprocalPrivate) *ReciprocalProof {
	vCom := public.CommitValue(private.X, private.S)

	mBlind := MustRandScalar()
	mCom := public.CommitWitness(private.Digits, private.M, mBlind)

	fs.AddPoint(new(bn256.G1).Add(vCom, mCom))

	e := fs.GetChallenge()

	Nm := public.Nd
	No := public.Np

	Nv := public.Nd + public.Nd + public.Np + 1
	Nl := Nv
	Nw := public.Nd + public.Nd + public.Np

	r := make([]*big.Int, public.Nd)
	for j := range r {
		r[j] = inv(add(private.Digits[j], e))
	}

	rBlind := MustRandScalar()
	rCom := public.CommitPoles(r, rBlind)

	v := []*big.Int{private.X}
	v = append(v, private.Digits...)
	v = append(v, private.M...)
	v = append(v, r...)

	wL := private.Digits
	wR := r
	wO := private.M

	am := oneVector(Nm)
	Wm := zeroMatrix(Nm, Nw)

	for i := 0; i < Nm; i++ {
		Wm[i][i+Nm] = minus(e)
	}

	al := zeroVector(Nl)
	Wl := zeroMatrix(Nl, Nw)

	// v
	base := bint(public.Np)
	for i := 0; i < Nm; i++ {
		Wl[0][i] = minus(pow(base, i))
	}

	// d
	for i := 0; i < Nm; i++ {
		Wl[i+1][i] = bint(-1)
	}

	// m
	for i := 0; i < No; i++ {
		Wl[i+Nm+1][i+2*Nm] = bint(-1)
	}

	// r
	for i := 0; i < Nm; i++ {
		for j := 0; j < Nm; j++ {
			Wl[i+Nm+No+1][j+Nm] = bint(1)
		}
	}

	for i := 0; i < Nm; i++ {
		Wl[i+Nm+No+1][i+Nm] = bint(0)
	}

	for i := 0; i < Nm; i++ {
		for j := 0; j < No; j++ {
			Wl[i+Nm+No+1][j+2*Nm] = minus(inv(add(e, bint(j))))
		}
	}

	circuit := &ArithmeticCircuitPublic{
		Nm:   Nm,
		Nl:   Nl,
		Nv:   Nv,
		Nw:   Nw,
		No:   No,
		K:    1,
		G:    public.G,
		GVec: public.GVec,
		HVec: public.HVec,
		Wm:   Wm,
		Wl:   Wl,
		Am:   am,
		Al:   al,
		Fl:   true,
		Fm:   false,
		F: func(typ PartitionType, index int) *int {
			if typ == PartitionLL && index < No { // map all to ll
				return &index
			}

			return nil
		},
		GVec_: public.GVec_,
		HVec_: public.HVec_,
	}

	prv := &ArithmeticCircuitPrivate{
		V:  [][]*big.Int{v},
		Sv: []*big.Int{add(add(mBlind, private.S), rBlind)},
		Wl: wL,
		Wr: wR,
		Wo: wO,
	}

	V := circuit.CommitCircuit(prv.V[0], prv.Sv[0])

	return &ReciprocalProof{
		ArithmeticCircuitProof: ProveCircuit(circuit, []*bn256.G1{V}, fs, prv),
		MCom:                   mCom,
		RCom:                   rCom,
	}
}

// VerifyRange verifies BP++ reciprocal argument range proof on arithmetic circuits. If err is nil then proof is valid.
// Use empty FiatShamirEngine for call.
func VerifyRange(public *ReciprocalPublic, VCom *bn256.G1, fs FiatShamirEngine, proof *ReciprocalProof) error {
	VMCom := new(bn256.G1).Add(VCom, proof.MCom)
	fs.AddPoint(VMCom)

	e := fs.GetChallenge()

	Nm := public.Nd
	No := public.Np

	Nv := public.Nd + public.Nd + public.Np + 1
	Nl := Nv
	Nw := public.Nd + public.Nd + public.Np

	am := oneVector(Nm)
	Wm := zeroMatrix(Nm, Nw)

	for i := 0; i < Nm; i++ {
		Wm[i][i+Nm] = minus(e)
	}

	al := zeroVector(Nl)
	Wl := zeroMatrix(Nl, Nw)

	// v
	base := bint(16)
	for i := 0; i < Nm; i++ {
		Wl[0][i] = minus(pow(base, i))
	}

	// d
	for i := 0; i < Nm; i++ {
		Wl[i+1][i] = bint(-1)
	}

	// m
	for i := 0; i < No; i++ {
		Wl[i+Nm+1][i+2*Nm] = bint(-1)
	}

	// r
	for i := 0; i < Nm; i++ {
		for j := 0; j < Nm; j++ {
			Wl[i+Nm+No+1][j+Nm] = bint(1)
		}
	}

	for i := 0; i < Nm; i++ {
		Wl[i+Nm+No+1][i+Nm] = bint(0)
	}

	for i := 0; i < Nm; i++ {
		for j := 0; j < No; j++ {
			Wl[i+Nm+No+1][j+2*Nm] = minus(inv(add(e, bint(j))))
		}
	}

	circuit := &ArithmeticCircuitPublic{
		Nm:   Nm,
		Nl:   Nl,
		Nv:   Nv,
		Nw:   Nw,
		No:   No,
		K:    1,
		G:    public.G,
		GVec: public.GVec,
		HVec: public.HVec,
		Wm:   Wm,
		Wl:   Wl,
		Am:   am,
		Al:   al,
		Fl:   true,
		Fm:   false,
		F: func(typ PartitionType, index int) *int {
			if typ == PartitionLL && index < No { // map all to ll
				return &index
			}

			return nil
		},
		GVec_: public.GVec_,
		HVec_: public.HVec_,
	}

	return VerifyCircuit(circuit, []*bn256.G1{new(bn256.G1).Add(VMCom, proof.RCom)}, fs, proof.ArithmeticCircuitProof)
}
