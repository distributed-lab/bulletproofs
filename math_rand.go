// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"crypto/rand"
	"github.com/cloudflare/bn256"
	"math/big"
)

func MustRandPoint() *bn256.G1 {
	_, p, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		panic(err)
	}
	return p
}

func MustRandScalar() *big.Int {
	v, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		panic(err)
	}
	return v
}
