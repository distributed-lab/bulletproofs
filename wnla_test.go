package bulletproofs

import (
	"math/big"
	"testing"
)

func TestWNLA(t *testing.T) {
	public := NewWeightNormLinearPublic(4, 2)

	// Private
	l := []*big.Int{bint(4), bint(5), bint(10), bint(1)}
	n := []*big.Int{bint(2), bint(1)}

	proof := ProveWNLA(public, public.Commit(l, n), NewKeccakFS(), l, n)
	if err := VerifyWNLA(public, proof, public.Commit(l, n), NewKeccakFS()); err != nil {
		panic(err)
	}
}
