// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import "math/big"

func UInt64Hex(x uint64) []*big.Int {
	resp := make([]*big.Int, 16)
	for i := 0; i < 16; i++ {
		resp[i] = big.NewInt(int64(x % 16))
		x /= 16
	}
	return resp
}

func HexMapping(digits []*big.Int) []*big.Int {
	resp := zeroVector(16)

	for _, d := range digits {
		dint := d.Int64()
		resp[dint] = add(resp[dint], bint(1))
	}

	return resp
}
