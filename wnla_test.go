package bulletproofs

import (
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"testing"
)

func TestWNLA(t *testing.T) {
	public := NewWeightNormLinearPublic(8, 4)
	spew.Dump(public)

	// Private
	l := []*big.Int{bint(4), bint(5), bint(10), bint(1), bint(99), bint(35), bint(1), bint(15)}
	n := []*big.Int{bint(1), bint(3), bint(42), bint(14)}

	proof := ProveWNLA(public, public.Commit(l, n), NewKeccakFS(), l, n)
	spew.Dump(proof)

	if err := VerifyWNLA(public, proof, public.Commit(l, n), NewKeccakFS()); err != nil {
		panic(err)
	}
}
