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

func (p *ReciprocalPublic) CommitPoles(r []*big.Int, s *big.Int) *bn256.G1 {
	res := new(bn256.G1).ScalarMult(p.HVec[0], s)
	res.Add(res, vectorPointScalarMul(p.HVec[9:], r))
	return res
}

// ProveRange generates zero knowledge proof that corresponding to the committed digits vector value lies in [0, 2^n) range.
// Use empty FiatShamirEngine for call.
func ProveRange(public *ReciprocalPublic, fs FiatShamirEngine, private *ReciprocalPrivate) *ReciprocalProof {
	vCom := public.CommitValue(private.X, private.S)
	fs.AddPoint(vCom)

	e := fs.GetChallenge()

	Nm := public.Nd
	No := public.Np

	Nv := public.Nd + 1
	Nl := Nv
	Nw := public.Nd + public.Nd + public.Np

	r := make([]*big.Int, public.Nd)
	for j := range r {
		r[j] = inv(add(private.Digits[j], e))
	}

	rBlind := MustRandScalar()
	rCom := public.CommitPoles(r, rBlind)

	v := []*big.Int{private.X}
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

	// r
	for i := 0; i < Nm; i++ {
		for j := 0; j < Nm; j++ {
			Wl[i+1][j+Nm] = bint(1)
		}
	}

	for i := 0; i < Nm; i++ {
		Wl[i+1][i+Nm] = bint(0)
	}

	for i := 0; i < Nm; i++ {
		for j := 0; j < No; j++ {
			Wl[i+1][j+2*Nm] = minus(inv(add(e, bint(j))))
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
		Sv: []*big.Int{add(private.S, rBlind)},
		Wl: wL,
		Wr: wR,
		Wo: wO,
	}

	V := circuit.CommitCircuit(prv.V[0], prv.Sv[0])

	return &ReciprocalProof{
		ArithmeticCircuitProof: ProveCircuit(circuit, []*bn256.G1{V}, fs, prv),
		V:                      rCom,
	}
}

// VerifyRange verifies BP++ reciprocal argument range proof on arithmetic circuits. If err is nil then proof is valid.
// Use empty FiatShamirEngine for call.
func VerifyRange(public *ReciprocalPublic, V *bn256.G1, fs FiatShamirEngine, proof *ReciprocalProof) error {
	fs.AddPoint(V)

	e := fs.GetChallenge()

	Nm := public.Nd
	No := public.Np

	Nv := public.Nd + 1
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
	base := bint(public.Np)
	for i := 0; i < Nm; i++ {
		Wl[0][i] = minus(pow(base, i))
	}

	// r
	for i := 0; i < Nm; i++ {
		for j := 0; j < Nm; j++ {
			Wl[i+1][j+Nm] = bint(1)
		}
	}

	for i := 0; i < Nm; i++ {
		Wl[i+1][i+Nm] = bint(0)
	}

	for i := 0; i < Nm; i++ {
		for j := 0; j < No; j++ {
			Wl[i+1][j+2*Nm] = minus(inv(add(e, bint(j))))
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

	return VerifyCircuit(circuit, []*bn256.G1{new(bn256.G1).Add(V, proof.V)}, fs, proof.ArithmeticCircuitProof)
}
