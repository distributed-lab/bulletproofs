// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

func pow(x *big.Int, y int) *big.Int {
	if y < 0 {
		return new(big.Int).Exp(inv(x), big.NewInt(-int64(y)), bn256.Order)
	}

	return new(big.Int).Exp(x, big.NewInt(int64(y)), bn256.Order)
}

func inv(x *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, bn256.Order)
}

func minus(x *big.Int) *big.Int {
	return sub(bint(0), x)
}

func powerOfTwo(x int) (p2 int) {
	p2 = 1
	for p2 < x {
		p2 *= 2
	}
	return
}

func bint(v int) *big.Int {
	return new(big.Int).Mod(new(big.Int).SetInt64(int64(v)), bn256.Order)
}

func bbool(v bool) *big.Int {
	if v {
		return bint(1)
	}

	return bint(0)
}

func zeroIfNil(x *big.Int) *big.Int {
	if x == nil {
		return bint(0)
	}
	return x
}

func add(x *big.Int, y *big.Int) *big.Int {
	x = zeroIfNil(x)
	y = zeroIfNil(y)
	return new(big.Int).Mod(new(big.Int).Add(x, y), bn256.Order)
}

func sub(x *big.Int, y *big.Int) *big.Int {
	x = zeroIfNil(x)
	y = zeroIfNil(y)
	return new(big.Int).Mod(new(big.Int).Sub(x, y), bn256.Order)
}

func mul(x *big.Int, y *big.Int) *big.Int {
	if x == nil || y == nil {
		return bint(0)
	}
	return new(big.Int).Mod(new(big.Int).Mul(x, y), bn256.Order)
}
