// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

// CommitCircuit creates a commitment for v vector and blinding s.
// Com = v[0]*G + s*H[0] + <v[1:], H[9:]>
func (p *ReciprocalPublic) CommitCircuit(v []*big.Int, s *big.Int) *bn256.G1 {
	res := new(bn256.G1).ScalarMult(p.G, v[0])
	res.Add(res, new(bn256.G1).ScalarMult(p.HVec[0], s))
	res.Add(res, vectorPointScalarMul(p.HVec[9:], v[1:]))
	return res
}

// ProveRange generates zero knowledge proof that corresponding to the committed digits vector value lies in [0, 2^n) range.
// Use empty FiatShamirEngine for call.
func ProveRange(public *ReciprocalPublic, V *bn256.G1, fs FiatShamirEngine, private *ReciprocalPrivate) *ReciprocalProof {
	fs.AddPoint(V)

	e := fs.GetChallenge()

	Nm := public.Nd
	No := public.Np

	Nv := public.Nd + public.Nd + public.Np
	Nl := Nv
	Nw := public.Nd + public.Nd + public.Np

	d := make([]*big.Int, public.Nd)
	for j := range d {
		d[j] = private.V[j]
	}

	r := make([]*big.Int, public.Nd)
	for j := range r {
		r[j] = inv(add(d[j], e))
	}

	m := make([]*big.Int, public.Np)
	for j := range m {
		m[j] = private.V[public.Nd+j]
	}

	v := append(d, r...) // Nv
	v = append(v, m...)

	wL := d
	wR := r
	wO := m

	am := oneVector(Nm)
	Wm := zeroMatrix(Nm, Nw)

	for i := 0; i < Nm; i++ {
		Wm[i][i+Nm] = minus(e)
	}

	al := zeroVector(Nl)
	Wl := zeroMatrix(Nl, Nw)

	for i := 0; i < Nm; i++ {
		Wl[i][i] = bint(-1)
	}

	for i := 0; i < Nm; i++ {
		for j := 0; j < Nm; j++ {
			Wl[i+Nm][j+Nm] = bint(1)
		}
	}

	for i := 0; i < Nm; i++ {
		Wl[i+Nm][i+Nm] = bint(0)
	}

	for i := 0; i < Nm; i++ {
		for j := 0; j < No; j++ {
			Wl[i+Nm][j+2*Nm] = minus(inv(add(e, bint(j))))
		}
	}

	for i := 0; i < No; i++ {
		Wl[i+2*Nm][i+2*Nm] = bint(-1)
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
		Sv: []*big.Int{private.Sv},
		Wl: wL,
		Wr: wR,
		Wo: wO,
	}

	V_ := circuit.CommitCircuit(v, private.Sv)

	return &ReciprocalProof{
		ArithmeticCircuitProof: ProveCircuit(circuit, []*bn256.G1{V_}, fs, prv),
		V:                      V_,
	}
}

// VerifyRange verifies BP++ reciprocal argument range proof on arithmetic circuits. If err is nil then proof is valid.
// Use empty FiatShamirEngine for call.
func VerifyRange(public *ReciprocalPublic, V *bn256.G1, fs FiatShamirEngine, proof *ReciprocalProof) error {
	fs.AddPoint(V)

	e := fs.GetChallenge()

	Nm := public.Nd
	No := public.Np

	Nv := public.Nd + public.Nd + public.Np
	Nl := Nv
	Nw := public.Nd + public.Nd + public.Np

	am := oneVector(Nm)
	Wm := zeroMatrix(Nm, Nw)

	for i := 0; i < Nm; i++ {
		Wm[i][i+Nm] = minus(e)
	}

	al := zeroVector(Nl)
	Wl := zeroMatrix(Nl, Nw)

	for i := 0; i < Nm; i++ {
		Wl[i][i] = bint(-1)
	}

	for i := 0; i < Nm; i++ {
		for j := 0; j < Nm; j++ {
			Wl[i+Nm][j+Nm] = bint(1)
		}
	}

	for i := 0; i < Nm; i++ {
		Wl[i+Nm][i+Nm] = bint(0)
	}

	for i := 0; i < Nm; i++ {
		for j := 0; j < No; j++ {
			Wl[i+Nm][j+2*Nm] = minus(inv(add(e, bint(j))))
		}
	}

	for i := 0; i < No; i++ {
		Wl[i+2*Nm][i+2*Nm] = bint(-1)
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

	return VerifyCircuit(circuit, []*bn256.G1{proof.V}, fs, proof.ArithmeticCircuitProof)
}

//wl_ := append(private.Wd, private.Wl...) // Np + Nm
//wo_ := private.Wo
//
//ro, rl, no, nl, lo, ll, Co, Cl := commitOL(public.ArithmeticCircuitPublic, wo_, wl_)
//
//fs.AddPoint(Cl)
//fs.AddPoint(Co)
//
//alpha := fs.GetChallenge()
//
//wi := append(private.Wo, private.Wl...) // No + Nm + Np
//wi = append(wi, private.Wd...)
//
//wv := make([]*big.Int, 0, public.Nw)
//for i := range private.V {
//	wv = append(wv, private.V[i]...)
//}
//
//wp_ := make([]*big.Int, public.Np)
//for i := range wp_ {
//	wpi := vectorMul(public.Wn[i], wi)
//	wpi = add(wpi, mul(bbool(public.Fm), wv[i]))
//	wpi = add(wpi, public.An[i])
//	wpi = mul(wpi, inv(add(alpha, private.Wd[i])))
//}
//
//wr_ := append(wp_, private.Wr...) // Np + Nm
//
//rr, nr, lr, Cr := commitR(public.ArithmeticCircuitPublic, wo_, wr_)
//fs.AddPoint(Cr)
//
//w := append(private.Wl, private.Wr...)
//w = append(w, private.Wo...)
//
//Wdwi := matrixMulOnVector(wi, public.Wd)
//Wpw := matrixMulOnVector(w, public.WpX(alpha))
//Wlw := matrixMulOnVector(w, public.Wl)
//
//Wl_w_ := append(Wdwi, Wpw...)
//Wl_w_ = append(Wl_w_, Wlw...)
