// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

// For scalars *big.Int

func zeroVector(n int) []*big.Int {
	res := make([]*big.Int, n)
	for i := range res {
		res[i] = big.NewInt(0)
	}
	return res
}

func oneVector(n int) []*big.Int {
	res := make([]*big.Int, n)
	for i := range res {
		res[i] = big.NewInt(1)
	}
	return res
}

func vectorAdd(a []*big.Int, b []*big.Int) []*big.Int {
	for len(a) < len(b) {
		a = append(a, bint(0))
	}

	for len(b) < len(a) {
		b = append(b, bint(0))
	}

	res := make([]*big.Int, len(a))
	for i := 0; i < len(res); i++ {
		res[i] = add(a[i], b[i])
	}

	return res
}

func vectorSub(a []*big.Int, b []*big.Int) []*big.Int {
	for len(a) < len(b) {
		a = append(a, bint(0))
	}

	for len(b) < len(a) {
		b = append(b, bint(0))
	}

	res := make([]*big.Int, len(a))
	for i := 0; i < len(res); i++ {
		res[i] = sub(a[i], b[i])
	}

	return res
}

func vectorMulOnScalar(a []*big.Int, c *big.Int) []*big.Int {
	res := make([]*big.Int, len(a))
	for i := range res {
		res[i] = mul(a[i], c)
	}
	return res
}

func vectorMul(a []*big.Int, b []*big.Int) *big.Int {
	for len(a) < len(b) {
		a = append(a, bint(0))
	}

	for len(b) < len(a) {
		b = append(b, bint(0))
	}

	res := big.NewInt(0)
	for i := 0; i < len(a); i++ {
		res = add(res, mul(a[i], b[i]))
	}
	return res
}

func weightVectorMul(a []*big.Int, b []*big.Int, mu *big.Int) *big.Int {
	for len(a) < len(b) {
		a = append(a, bint(0))
	}

	for len(b) < len(a) {
		b = append(b, bint(0))
	}

	res := big.NewInt(0)
	exp := new(big.Int).Set(mu)

	for i := 0; i < len(a); i++ {
		res = add(res, mul(mul(a[i], b[i]), exp))
		exp = mul(exp, mu)
	}
	return res
}

// For points *bn256.G1

func vectorPointScalarMul(g []*bn256.G1, a []*big.Int) *bn256.G1 {
	if len(g) == 0 {
		return new(bn256.G1).ScalarBaseMult(bint(0))
	}

	for len(a) < len(g) {
		a = append(a, bint(0))
	}

	res := new(bn256.G1).ScalarMult(g[0], a[0])
	for i := 1; i < len(g); i++ {
		res.Add(res, new(bn256.G1).ScalarMult(g[i], a[i]))
	}
	return res
}

func vectorPointsAdd(a, b []*bn256.G1) []*bn256.G1 {
	for len(a) < len(b) {
		a = append(a, new(bn256.G1).ScalarBaseMult(bint(0)))
	}

	for len(b) < len(a) {
		b = append(b, new(bn256.G1).ScalarBaseMult(bint(0)))
	}

	res := make([]*bn256.G1, len(a))
	for i := range res {
		res[i] = new(bn256.G1).Add(a[i], b[i])
	}
	return res
}

func vectorPointMulOnScalar(g []*bn256.G1, a *big.Int) []*bn256.G1 {
	res := make([]*bn256.G1, len(g))
	for i := range res {
		res[i] = new(bn256.G1).ScalarMult(g[i], a)
	}
	return res
}

func vectorTensorMul(a, b []*big.Int) []*big.Int {
	res := make([]*big.Int, 0, len(a)*len(b))

	for i := range b {
		res = append(res, vectorMulOnScalar(a, b[i])...)
	}
	return res
}

func e(v *big.Int, a int) []*big.Int {
	val := bint(1)
	res := make([]*big.Int, a)
	for i := range res {
		res[i] = val
		val = mul(val, v)
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
