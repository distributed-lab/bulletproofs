// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import "math/big"

func diagInv(x *big.Int, n int) [][]*big.Int {
	var res [][]*big.Int = make([][]*big.Int, n)
	inv := inv(x)
	val := new(big.Int).Set(inv)

	for i := 0; i < n; i++ {
		res[i] = make([]*big.Int, n)

		for j := 0; j < n; j++ {
			res[i][j] = bint(0)

			if i == j {
				res[i][j] = val
				val = mul(val, inv)
			}
		}
	}

	return res
}

func vectorMulOnMatrix(a []*big.Int, m [][]*big.Int) []*big.Int {
	var res []*big.Int

	for j := 0; j < len(m[0]); j++ {
		var column []*big.Int

		for i := 0; i < len(m); i++ {
			column = append(column, m[i][j])
		}

		res = append(res, vectorMul(a, column))
	}

	return res
}
