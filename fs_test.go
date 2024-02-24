package bulletproofs

import (
	"github.com/cloudflare/bn256"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"testing"
)

func TestKeccakFS(t *testing.T) {
	fs := NewKeccakFS()
	fs.AddNumber(bint(1))
	fs.AddNumber(bint(2))

	c1 := fs.GetChallenge()

	c2 := new(big.Int).Mod(
		new(big.Int).SetBytes(
			crypto.Keccak256(
				scalarTo32Byte(bint(1)),
				scalarTo32Byte(bint(2)),
			),
		),
		bn256.Order,
	)

	if c1.Cmp(c2) != 0 {
		panic("test failed")
	}

	fs.AddNumber(bint(3))
	c3 := fs.GetChallenge()

	c4 := new(big.Int).Mod(
		new(big.Int).SetBytes(
			crypto.Keccak256(
				scalarTo32Byte(bint(1)),
				scalarTo32Byte(bint(2)),
				scalarTo32Byte(bint(3)),
			),
		),
		bn256.Order,
	)

	if c3.Cmp(c4) != 0 {
		panic("test failed")
	}
}
