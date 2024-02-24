package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

func inv(x *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, bn256.Order)
}

func bint(v int) *big.Int {
	return new(big.Int).Mod(new(big.Int).SetInt64(int64(v)), bn256.Order)
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
