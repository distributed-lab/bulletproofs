// Package bulletproofs
// Copyright 2024 Distributed Lab. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

type FiatShamirEngine interface {
	AddPoint(*bn256.G1)
	AddNumber(*big.Int)
	GetChallenge() *big.Int
}

type KeccakFS struct {
	state   crypto.KeccakState
	counter int
}

func NewKeccakFS() FiatShamirEngine {
	return &KeccakFS{state: crypto.NewKeccakState()}
}

func (k *KeccakFS) AddPoint(p *bn256.G1) {
	if _, err := k.state.Write(p.Marshal()); err != nil {
		panic(err)
	}
}

func (k *KeccakFS) AddNumber(v *big.Int) {
	if _, err := k.state.Write(scalarTo32Byte(v)); err != nil {
		panic(err)
	}
}

func (k *KeccakFS) GetChallenge() *big.Int {
	k.counter++
	k.AddNumber(bint(k.counter))
	return new(big.Int).Mod(new(big.Int).SetBytes(k.state.Sum(nil)), bn256.Order)
}

func scalarTo32Byte(s *big.Int) []byte {
	arr := s.Bytes()
	if len(arr) >= 32 {
		return arr[:32]
	}

	res := make([]byte, 32-len(arr))
	return append(res, arr...)
}
