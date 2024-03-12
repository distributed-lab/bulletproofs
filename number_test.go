// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"fmt"
	"testing"
)

func TestUInt64Hex(t *testing.T) {
	x := uint64(0xab4f0540ab4f0540)
	fmt.Println(UInt64Hex(x))             // [0 4 5 0 15 4 11 10 0 4 5 0 15 4 11 10]
	fmt.Println(HexMapping(UInt64Hex(x))) // [4 0 0 0 4 2 0 0 0 0 2 2 0 0 0 2]
}
