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
func (p *ArithmeticCircuitPublic) CommitCircuit(v []*big.Int, s *big.Int) *bn256.G1 {
	res := new(bn256.G1).ScalarMult(p.G, v[0])
	res.Add(res, new(bn256.G1).ScalarMult(p.HVec[0], s))
	res.Add(res, vectorPointScalarMul(p.HVec[9:], v[1:]))
	return res
}

// VerifyCircuit verifies BP++ arithmetic circuit zero-knowledge proof using WNLA protocol. If err is nil then proof is valid.
// Use empty FiatShamirEngine for call.
func VerifyCircuit(public *ArithmeticCircuitPublic, V []*bn256.G1, fs FiatShamirEngine, proof *ArithmeticCircuitProof) error {
	fs.AddPoint(proof.CL)
	fs.AddPoint(proof.CR)
	fs.AddPoint(proof.CO)

	// Generates challenges using Fiat-Shamir heuristic
	ro := fs.GetChallenge()
	lambda := fs.GetChallenge()
	beta := fs.GetChallenge()
	delta := fs.GetChallenge()

	MlnL, MmnL, MlnR, MmnR := calculateMRL(public)
	MlnO, MmnO, MllL, MmlL, MllR, MmlR, MllO, MmlO := calculateMO(public)

	mu := mul(ro, ro)

	lcomb := func(i int) *big.Int {
		return add(
			mul(bbool(public.Fl), pow(lambda, public.Nv*i)),
			mul(bbool(public.Fm), pow(mu, public.Nv*i+1)),
		)
	}

	// Calculate linear combination of V
	V_ := func() *bn256.G1 {
		var V_ = new(bn256.G1).ScalarBaseMult(bint(0)) // set infinite

		for i := 0; i < public.K; i++ {
			V_ = V_.Add(V_, new(bn256.G1).ScalarMult(
				V[i],
				lcomb(i),
			))
		}

		return V_.ScalarMult(V_, bint(2))
	}()

	// Calculate lambda vector (nl == nv * k)
	lambdaVec := vectorAdd(
		vectorTensorMul(vectorMulOnScalar(e(lambda, public.Nv), mu), e(pow(mu, public.Nv), public.K)),
		vectorTensorMul(e(mu, public.Nv), e(pow(lambda, public.Nv), public.K)),
	)

	lambdaVec = vectorMulOnScalar(lambdaVec, bbool(public.Fl && public.Fm))
	lambdaVec = vectorSub(e(lambda, public.Nl), lambdaVec) //Nl

	// Calculate mu vector
	muVec := vectorMulOnScalar(e(mu, public.Nm), mu) // Nm

	// Calculate coefficients clX, X = {L,R,O}
	muDiagInv := diagInv(mu, public.Nm) // Nm*Nm

	cnL := vectorMulOnMatrix(vectorSub(vectorMulOnMatrix(lambdaVec, MlnL), vectorMulOnMatrix(muVec, MmnL)), muDiagInv) // Nm
	cnR := vectorMulOnMatrix(vectorSub(vectorMulOnMatrix(lambdaVec, MlnR), vectorMulOnMatrix(muVec, MmnR)), muDiagInv) // Nm
	cnO := vectorMulOnMatrix(vectorSub(vectorMulOnMatrix(lambdaVec, MlnO), vectorMulOnMatrix(muVec, MmnO)), muDiagInv) // Nm

	clL := vectorSub(vectorMulOnMatrix(lambdaVec, MllL), vectorMulOnMatrix(muVec, MmlL)) // Nv
	clR := vectorSub(vectorMulOnMatrix(lambdaVec, MllR), vectorMulOnMatrix(muVec, MmlR)) // Nv
	clO := vectorSub(vectorMulOnMatrix(lambdaVec, MllO), vectorMulOnMatrix(muVec, MmlO)) // Nv

	fs.AddPoint(proof.CS)

	// Select random t using Fiat-Shamir heuristic
	t := fs.GetChallenge()
	tinv := inv(t)
	t2 := mul(t, t)
	t3 := mul(t2, t)

	pnT := vectorMulOnScalar(cnO, mul(inv(delta), t3))
	pnT = vectorSub(pnT, vectorMulOnScalar(cnL, t2))
	pnT = vectorAdd(pnT, vectorMulOnScalar(cnR, t))

	psT := weightVectorMul(pnT, pnT, mu)
	psT = add(psT, mul(bint(2), mul(vectorMul(lambdaVec, public.Al), t3)))
	psT = sub(psT, mul(bint(2), mul(vectorMul(muVec, public.Am), t3)))

	PT := new(bn256.G1).ScalarMult(public.G, psT)
	PT.Add(PT, vectorPointScalarMul(public.GVec, pnT))

	cr_T := []*big.Int{
		bint(1),
		mul(beta, tinv),
		mul(beta, t),
		mul(beta, t2),
		mul(beta, t3),
		mul(beta, mul(t, t3)),
		mul(beta, mul(t2, t3)),
		mul(beta, mul(t3, t3)),
		mul(beta, mul(mul(t3, t), t3)),
	} // 9

	cl0 := vectorSub(
		vectorMulOnScalar(e(lambda, public.Nv)[1:], bbool(public.Fl)),
		vectorMulOnScalar(vectorMulOnScalar(e(mu, public.Nv)[1:], mu), bbool(public.Fm)),
	)

	cl_T := vectorMulOnScalar(clO, mul(t3, inv(delta)))
	cl_T = vectorSub(cl_T, vectorMulOnScalar(clL, t2))
	cl_T = vectorAdd(cl_T, vectorMulOnScalar(clR, t))
	cl_T = vectorMulOnScalar(cl_T, bint(2))
	cl_T = vectorSub(cl_T, cl0)

	cT := append(cr_T, cl_T...)

	CT := new(bn256.G1).Add(PT, new(bn256.G1).ScalarMult(proof.CS, tinv))
	CT.Add(CT, new(bn256.G1).ScalarMult(proof.CO, minus(delta)))
	CT.Add(CT, new(bn256.G1).ScalarMult(proof.CL, t))
	CT.Add(CT, new(bn256.G1).ScalarMult(proof.CR, minus(t2)))
	CT.Add(CT, new(bn256.G1).ScalarMult(V_, t3))

	return VerifyWNLA(
		&WeightNormLinearPublic{
			G:    public.G,
			GVec: append(public.GVec, public.GVec_...),
			HVec: append(public.HVec, public.HVec_...),
			C:    cT,
			Ro:   ro,
			Mu:   mu,
		},
		proof.WNLA,
		CT,
		fs,
	)
}

// ProveCircuit generates zero knowledge proof that witness satisfies BP++ arithmetic circuit.
// Use empty FiatShamirEngine for call.
func ProveCircuit(public *ArithmeticCircuitPublic, fs FiatShamirEngine, private *ArithmeticCircuitPrivate) *ArithmeticCircuitProof {
	ro, rl, no, nl, lo, ll, Co, Cl := commitOL(public, private.Wo, private.Wl)

	rr, nr, lr, Cr := commitR(public, private.Wo, private.Wr)

	return innerArithmeticCircuitProve(public, fs, private,
		[][]*big.Int{rl, rr, ro},
		[][]*big.Int{nl, nr, no},
		[][]*big.Int{ll, lr, lo},
		[]*bn256.G1{Cl, Cr, Co},
	)
}

func commitOL(public *ArithmeticCircuitPublic, wo, wl []*big.Int) (ro []*big.Int, rl []*big.Int, no []*big.Int, nl []*big.Int, lo []*big.Int, ll []*big.Int, Co *bn256.G1, Cl *bn256.G1) {
	// contains random values, except several positions
	ro = []*big.Int{MustRandScalar(), MustRandScalar(), MustRandScalar(), MustRandScalar(), bint(0), MustRandScalar(), MustRandScalar(), MustRandScalar(), bint(0)} // 9
	rl = []*big.Int{MustRandScalar(), MustRandScalar(), MustRandScalar(), bint(0), MustRandScalar(), MustRandScalar(), MustRandScalar(), bint(0), bint(0)}          // 9

	nl = wl // Nm

	no = make([]*big.Int, public.Nm) // Nm
	for j := range no {
		no[j] = big.NewInt(0)

		if i := public.F(PartitionNO, j); i != nil {
			no[j].Set(wo[*i])
		}
	}

	lo = make([]*big.Int, public.Nv) // Nv
	for j := range lo {
		lo[j] = big.NewInt(0)

		if i := public.F(PartitionLO, j); i != nil {
			lo[j].Set(wo[*i])
		}
	}

	ll = make([]*big.Int, public.Nv) // Nv
	for j := range lo {
		ll[j] = big.NewInt(0)

		if i := public.F(PartitionLL, j); i != nil {
			ll[j].Set(wo[*i])
		}
	}

	Co = vectorPointScalarMul(public.HVec, append(ro, lo...))
	Co.Add(Co, vectorPointScalarMul(public.GVec, no))

	Cl = vectorPointScalarMul(public.HVec, append(rl, ll...))
	Cl.Add(Cl, vectorPointScalarMul(public.GVec, nl))

	return
}

func commitR(public *ArithmeticCircuitPublic, wo, wr []*big.Int) (rr []*big.Int, nr []*big.Int, lr []*big.Int, Cr *bn256.G1) {
	// contains random values, except several positions
	rr = []*big.Int{MustRandScalar(), MustRandScalar(), bint(0), MustRandScalar(), MustRandScalar(), MustRandScalar(), bint(0), bint(0), bint(0)} // 9

	nr = wr // Nm

	// Creates commits Cr also map input witness using f partition func
	lr = make([]*big.Int, public.Nv) // Nv
	for j := range lr {
		lr[j] = big.NewInt(0)

		if i := public.F(PartitionLR, j); i != nil {
			lr[j].Set(wo[*i])
		}
	}

	Cr = vectorPointScalarMul(public.HVec, append(rr, lr...))
	Cr.Add(Cr, vectorPointScalarMul(public.GVec, nr))
	return
}

func innerArithmeticCircuitProve(public *ArithmeticCircuitPublic, fs FiatShamirEngine, private *ArithmeticCircuitPrivate, r, n, l [][]*big.Int, C []*bn256.G1) *ArithmeticCircuitProof {
	rl := r[0] // 8
	rr := r[1] // 8
	ro := r[2] // 8

	ll := l[0] // Nv
	lr := l[1] // Nv
	lo := l[2] // Nv

	nl := n[0] // Nm
	nr := n[1] // Nm
	no := n[2] // Nm

	Cl := C[0]
	Cr := C[1]
	Co := C[2]

	proof := &ArithmeticCircuitProof{
		CL: Cl,
		CR: Cr,
		CO: Co,
	}

	fs.AddPoint(Cl)
	fs.AddPoint(Cr)
	fs.AddPoint(Co)

	// Generates challenges using Fiat-Shamir heuristic
	rho := fs.GetChallenge()
	lambda := fs.GetChallenge()
	beta := fs.GetChallenge()
	delta := fs.GetChallenge()

	MlnL, MmnL, MlnR, MmnR := calculateMRL(public)
	MlnO, MmnO, MllL, MmlL, MllR, MmlR, MllO, MmlO := calculateMO(public)

	mu := mul(rho, rho)

	// Calculate lambda vector (nl == nv * k)
	lambdaVec := vectorAdd(
		vectorTensorMul(vectorMulOnScalar(e(lambda, public.Nv), mu), e(pow(mu, public.Nv), public.K)),
		vectorTensorMul(e(mu, public.Nv), e(pow(lambda, public.Nv), public.K)),
	)

	lambdaVec = vectorMulOnScalar(lambdaVec, bbool(public.Fl && public.Fm))
	lambdaVec = vectorSub(e(lambda, public.Nl), lambdaVec) //Nl

	// Calculate mu vector
	muVec := vectorMulOnScalar(e(mu, public.Nm), mu) // Nm

	// Calculate coefficients clX, X = {L,R,O}
	muDiagInv := diagInv(mu, public.Nm) // Nm*Nm

	cnL := vectorMulOnMatrix(vectorSub(vectorMulOnMatrix(lambdaVec, MlnL), vectorMulOnMatrix(muVec, MmnL)), muDiagInv) // Nm
	cnR := vectorMulOnMatrix(vectorSub(vectorMulOnMatrix(lambdaVec, MlnR), vectorMulOnMatrix(muVec, MmnR)), muDiagInv) // Nm
	cnO := vectorMulOnMatrix(vectorSub(vectorMulOnMatrix(lambdaVec, MlnO), vectorMulOnMatrix(muVec, MmnO)), muDiagInv) // Nm

	clL := vectorSub(vectorMulOnMatrix(lambdaVec, MllL), vectorMulOnMatrix(muVec, MmlL)) // Nv
	clR := vectorSub(vectorMulOnMatrix(lambdaVec, MllR), vectorMulOnMatrix(muVec, MmlR)) // Nv
	clO := vectorSub(vectorMulOnMatrix(lambdaVec, MllO), vectorMulOnMatrix(muVec, MmlO)) // Nv

	// Prover computes
	ls := make([]*big.Int, public.Nv) // Nv
	for i := range ls {
		ls[i] = MustRandScalar()
	}

	ns := make([]*big.Int, public.Nm) // Nm
	for i := range ns {
		ns[i] = MustRandScalar()
	}

	lcomb := func(i int) *big.Int {
		return add(
			mul(bbool(public.Fl), pow(lambda, public.Nv*i)),
			mul(bbool(public.Fm), pow(mu, public.Nv*i+1)),
		)
	}

	// Calc linear combination of v[][0]
	v_ := func() *big.Int {
		v_ := bint(0)

		for i := 0; i < public.K; i++ {
			v_ = add(v_, mul(
				private.V[i][0],
				lcomb(i),
			))
		}

		return mul(v_, bint(2))
	}()

	rv := zeroVector(9) // 9
	rv[0] = func() *big.Int {
		rv1 := bint(0)

		for i := 0; i < public.K; i++ {
			rv1 = add(rv1, mul(
				private.Sv[i],
				lcomb(i),
			))
		}

		return mul(rv1, bint(2))
	}()

	// Calc linear combination of v[][1:]
	v_1 := func() []*big.Int {
		var v_1 = zeroVector(1)

		for i := 0; i < public.K; i++ {
			v_1 = vectorAdd(v_1, vectorMulOnScalar(
				private.V[i][1:],
				lcomb(i),
			))
		}

		return vectorMulOnScalar(v_1, bint(2))
	}()

	cl0 := vectorSub(
		vectorMulOnScalar(e(lambda, public.Nv)[1:], bbool(public.Fl)),
		vectorMulOnScalar(vectorMulOnScalar(e(mu, public.Nv)[1:], mu), bbool(public.Fm)),
	)

	// Define f'(t):
	f_ := make(map[int]*big.Int)

	f_[-2] = sub(f_[-2], weightVectorMul(ns, ns, mu))

	f_[-1] = add(f_[-1], vectorMul(cl0, ls))
	f_[-1] = add(f_[-1], mul(mul(bint(2), delta), weightVectorMul(ns, no, mu)))

	f_[0] = sub(f_[0], mul(bint(2), vectorMul(clR, ls)))
	f_[0] = sub(f_[0], mul(delta, vectorMul(cl0, lo)))
	f_[0] = sub(f_[0], mul(weightVectorMul(ns, vectorAdd(nl, cnR), mu), bint(2)))
	f_[0] = sub(f_[0], mul(mul(delta, delta), weightVectorMul(no, no, mu)))

	f_[1] = add(f_[1], mul(bint(2), vectorMul(clL, ls)))
	f_[1] = add(f_[1], mul(bint(2), mul(delta, vectorMul(clR, lo))))
	f_[1] = add(f_[1], vectorMul(cl0, ll))
	f_[1] = add(f_[1], mul(weightVectorMul(ns, vectorAdd(nr, cnL), mu), bint(2)))
	f_[1] = add(f_[1], mul(weightVectorMul(no, vectorAdd(nl, cnR), mu), mul(bint(2), delta)))

	f_[2] = add(f_[2], weightVectorMul(cnR, cnR, mu))
	f_[2] = sub(f_[2], mul(bint(2), mul(inv(delta), vectorMul(clO, ls))))
	f_[2] = sub(f_[2], mul(bint(2), mul(delta, vectorMul(clL, lo))))
	f_[2] = sub(f_[2], mul(bint(2), vectorMul(clR, ll)))
	f_[2] = sub(f_[2], vectorMul(cl0, lr))
	f_[2] = sub(f_[2], mul(mul(bint(2), inv(delta)), weightVectorMul(ns, cnO, mu)))
	f_[2] = sub(f_[2], mul(mul(bint(2), delta), weightVectorMul(no, vectorAdd(nr, cnL), mu)))
	f_[2] = sub(f_[2], weightVectorMul(vectorAdd(nl, cnR), vectorAdd(nl, cnR), mu))

	// f_3[3] should be zero

	f_[4] = add(f_[4], mul(mul(bint(2), inv(delta)), weightVectorMul(cnO, cnR, mu)))
	f_[4] = add(f_[4], weightVectorMul(cnL, cnL, mu))
	f_[4] = sub(f_[4], mul(mul(bint(2), inv(delta)), vectorMul(clO, ll)))
	f_[4] = sub(f_[4], mul(bint(2), vectorMul(clL, lr)))
	f_[4] = sub(f_[4], mul(bint(2), vectorMul(clR, v_1)))
	f_[4] = sub(f_[4], mul(mul(bint(2), inv(delta)), weightVectorMul(vectorAdd(nl, cnR), cnO, mu)))
	f_[4] = sub(f_[4], weightVectorMul(vectorAdd(nr, cnL), vectorAdd(nr, cnL), mu))

	f_[5] = sub(f_[5], mul(mul(bint(2), inv(delta)), weightVectorMul(cnO, cnL, mu)))
	f_[5] = add(f_[5], mul(mul(bint(2), inv(delta)), vectorMul(clO, lr)))
	f_[5] = add(f_[5], mul(bint(2), vectorMul(clL, v_1)))
	f_[5] = add(f_[5], mul(mul(bint(2), inv(delta)), weightVectorMul(vectorAdd(nr, cnL), cnO, mu)))

	f_[6] = sub(f_[6], mul(mul(bint(2), inv(delta)), vectorMul(clO, v_1)))

	f_[3] = add(f_[3], mul(bint(2), sub(vectorMul(lambdaVec, public.Al), vectorMul(muVec, public.Am))))
	f_[3] = sub(f_[3], mul(bint(2), weightVectorMul(cnL, cnR, mu))) // 2+1
	f_[3] = add(f_[3], v_)
	f_[3] = add(f_[3], mul(bint(2), vectorMul(clO, lo)))
	f_[3] = add(f_[3], mul(bint(2), vectorMul(clL, ll)))
	f_[3] = add(f_[3], mul(bint(2), vectorMul(clR, lr)))
	f_[3] = add(f_[3], vectorMul(cl0, v_1))
	f_[3] = add(f_[3], mul(weightVectorMul(no, cnO, mu), bint(2)))
	f_[3] = add(f_[3], mul(weightVectorMul(vectorAdd(nl, cnR), vectorAdd(nr, cnL), mu), bint(2)))

	ch_beta_inv := inv(beta)

	rs := []*big.Int{
		add(f_[-1], mul(beta, mul(delta, ro[1]))),
		mul(f_[-2], ch_beta_inv),
		sub(mul(add(f_[0], mul(delta, ro[0])), ch_beta_inv), rl[1]),
		add(mul(sub(f_[1], rl[0]), ch_beta_inv), add(rr[1], mul(delta, ro[2]))),
		add(mul(add(f_[2], rr[0]), ch_beta_inv), sub(mul(delta, ro[3]), rl[2])),
		minus(mul(rv[0], ch_beta_inv)),
		add(mul(f_[4], ch_beta_inv), add(mul(delta, ro[5]), sub(rr[3], rl[4]))),
		add(mul(f_[5], ch_beta_inv), sub(add(rr[4], mul(delta, ro[6])), rl[5])),
		add(mul(f_[6], ch_beta_inv), add(sub(mul(delta, ro[7]), rl[6]), rr[5])),
	} // 9

	Cs := vectorPointScalarMul(public.HVec, append(rs, ls...))
	Cs.Add(Cs, vectorPointScalarMul(public.GVec, ns))

	proof.CS = Cs

	fs.AddPoint(Cs)

	// Select random t using Fiat-Shamir heuristic
	t := fs.GetChallenge()
	tinv := inv(t)
	t2 := mul(t, t)
	t3 := mul(t2, t)

	lT := vectorMulOnScalar(append(rs, ls...), tinv)
	lT = vectorSub(lT, vectorMulOnScalar(append(ro, lo...), delta))
	lT = vectorAdd(lT, vectorMulOnScalar(append(rl, ll...), t))
	lT = vectorSub(lT, vectorMulOnScalar(append(rr, lr...), t2))
	lT = vectorAdd(lT, vectorMulOnScalar(append(rv, v_1...), t3))

	pnT := vectorMulOnScalar(cnO, mul(inv(delta), t3))
	pnT = vectorSub(pnT, vectorMulOnScalar(cnL, t2))
	pnT = vectorAdd(pnT, vectorMulOnScalar(cnR, t))

	psT := weightVectorMul(pnT, pnT, mu)
	psT = add(psT, mul(bint(2), mul(vectorMul(lambdaVec, public.Al), t3)))
	psT = sub(psT, mul(bint(2), mul(vectorMul(muVec, public.Am), t3)))

	n_T := vectorMulOnScalar(ns, tinv)
	n_T = vectorSub(n_T, vectorMulOnScalar(no, delta))
	n_T = vectorAdd(n_T, vectorMulOnScalar(nl, t))
	n_T = vectorSub(n_T, vectorMulOnScalar(nr, t2))

	nT := vectorAdd(pnT, n_T)

	PT := new(bn256.G1).ScalarMult(public.G, psT)
	PT.Add(PT, vectorPointScalarMul(public.GVec, pnT))

	cr_T := []*big.Int{
		bint(1),
		mul(beta, tinv),
		mul(beta, t),
		mul(beta, t2),
		mul(beta, t3),
		mul(beta, mul(t, t3)),
		mul(beta, mul(t2, t3)),
		mul(beta, mul(t3, t3)),
		mul(beta, mul(mul(t3, t), t3)),
	} // 9

	cl_T := vectorMulOnScalar(clO, mul(t3, inv(delta)))
	cl_T = vectorSub(cl_T, vectorMulOnScalar(clL, t2))
	cl_T = vectorAdd(cl_T, vectorMulOnScalar(clR, t))
	cl_T = vectorMulOnScalar(cl_T, bint(2))
	cl_T = vectorSub(cl_T, cl0)

	cT := append(cr_T, cl_T...)

	vT := add(psT, mul(v_, t3))

	CT := new(bn256.G1).ScalarMult(public.G, vT)
	CT.Add(CT, vectorPointScalarMul(public.HVec, lT))
	CT.Add(CT, vectorPointScalarMul(public.GVec, nT))

	// Extend vectors with zeros up to 2^i

	for len(lT) < len(public.HVec)+len(public.HVec_) {
		lT = append(lT, bint(0))
		cT = append(cT, bint(0))
	}

	for len(nT) < len(public.GVec_)+len(public.GVec_) {
		nT = append(nT, bint(0))
	}

	proof.WNLA = ProveWNLA(
		&WeightNormLinearPublic{
			G:    public.G,
			GVec: append(public.GVec, public.GVec_...),
			HVec: append(public.HVec, public.HVec_...),
			C:    cT,
			Ro:   rho,
			Mu:   mu,
		},
		CT,
		fs,
		lT,
		nT,
	)
	return proof
}

func calculateMRL(public *ArithmeticCircuitPublic) (MlnL, MmnL, MlnR, MmnR [][]*big.Int) {
	for i := 0; i < public.Nl; i++ { // Nl * Nm
		MlnL = append(MlnL, public.Wl[i][:public.Nm])
	}

	for i := 0; i < public.Nm; i++ { // Nm * Nm
		MmnL = append(MmnL, public.Wm[i][:public.Nm])
	}

	for i := 0; i < public.Nl; i++ { // Nl*Nm
		MlnR = append(MlnR, public.Wl[i][public.Nm:public.Nm*2])
	}

	for i := 0; i < public.Nm; i++ { // Nm*Nm
		MmnR = append(MmnR, public.Wm[i][public.Nm:public.Nm*2])
	}

	return
}

func calculateMO(public *ArithmeticCircuitPublic) (MlnO, MmnO, MllL, MmlL, MllR, MmlR, MllO, MmlO [][]*big.Int) {
	var WlO [][]*big.Int // Nl*No
	for i := 0; i < public.Nl; i++ {
		WlO = append(WlO, public.Wl[i][public.Nm*2:])
	}

	var WmO [][]*big.Int // Nm*No
	for i := 0; i < public.Nm; i++ {
		WmO = append(WmO, public.Wm[i][public.Nm*2:])
	}

	//ManO, a = {l,m}

	for i := 0; i < public.Nl; i++ { // Nl*Nm
		MlnO = append(MlnO, make([]*big.Int, public.Nm))

		for j := 0; j < public.Nm; j++ {
			MlnO[i][j] = big.NewInt(0)

			if j_ := public.F(PartitionNO, j); j_ != nil {
				MlnO[i][j].Set(WlO[i][*j_])
			}
		}
	}

	for i := 0; i < public.Nm; i++ { // Nm*Nm
		MmnO = append(MmnO, make([]*big.Int, public.Nm))

		for j := 0; j < public.Nm; j++ {
			MmnO[i][j] = big.NewInt(0)

			if j_ := public.F(PartitionNO, j); j_ != nil {
				MmnO[i][j].Set(WmO[i][*j_])
			}
		}
	}

	// MalX, a = {l,m}, X = {L,R,O}

	// L
	for i := 0; i < public.Nl; i++ { // Nl*Nv
		MllL = append(MllL, make([]*big.Int, public.Nv))

		for j := 0; j < public.Nv; j++ {
			MllL[i][j] = big.NewInt(0)

			if j_ := public.F(PartitionLL, j); j_ != nil {
				MllL[i][j].Set(WlO[i][*j_])
			}
		}
	}

	for i := 0; i < public.Nm; i++ { // Nm*Nv
		MmlL = append(MmlL, make([]*big.Int, public.Nv))

		for j := 0; j < public.Nv; j++ {
			MmlL[i][j] = big.NewInt(0)

			if j_ := public.F(PartitionLL, j); j_ != nil {
				MmlL[i][j].Set(WmO[i][*j_])
			}
		}
	}

	// R
	for i := 0; i < public.Nl; i++ { // Nl*Nv
		MllR = append(MllR, make([]*big.Int, public.Nv))

		for j := 0; j < public.Nv; j++ {
			MllR[i][j] = big.NewInt(0)

			if j_ := public.F(PartitionLR, j); j_ != nil {
				MllR[i][j].Set(WlO[i][*j_])
			}
		}
	}

	for i := 0; i < public.Nm; i++ { // Nm*Nv
		MmlR = append(MmlR, make([]*big.Int, public.Nv))

		for j := 0; j < public.Nv; j++ {
			MmlR[i][j] = big.NewInt(0)

			if j_ := public.F(PartitionLR, j); j_ != nil {
				MmlR[i][j].Set(WmO[i][*j_])
			}
		}
	}

	// O
	for i := 0; i < public.Nl; i++ { // Nl*Nv
		MllO = append(MllO, make([]*big.Int, public.Nv))

		for j := 0; j < public.Nv; j++ {
			MllO[i][j] = big.NewInt(0)

			if j_ := public.F(PartitionLO, j); j_ != nil {
				MllO[i][j].Set(WlO[i][*j_])
			}
		}
	}

	for i := 0; i < public.Nm; i++ { // Nm*Nv
		MmlO = append(MmlO, make([]*big.Int, public.Nv))

		for j := 0; j < public.Nv; j++ {
			MmlO[i][j] = big.NewInt(0)

			if j_ := public.F(PartitionLO, j); j_ != nil {
				MmlO[i][j].Set(WmO[i][*j_])
			}
		}
	}

	return
}
