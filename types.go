package bulletproofs

import (
	"crypto/rand"
	"github.com/cloudflare/bn256"
	"math/big"
)

// WeightNormLinearArgumentProof contains the proof of knowledge of vectors L, N for corresponding commitment C (is not
// included into the proof structure).
type WeightNormLinearArgumentProof struct {
	R, X []*bn256.G1
	L, N []*big.Int
}

// WeightNormLinearPublic contains the public values to be used in weight norm linear argument proof.
// The GVec and HVec sizes are recommended to be a powers of 2 and equal to the `n` and `l` private vector sizes.
type WeightNormLinearPublic struct {
	G          *bn256.G1
	GVec, HVec []*bn256.G1
	C          []*big.Int
	Ro, Mu     *big.Int // mu = ro^2
}

func NewWeightNormLinearPublic(lLen int, nLen int) *WeightNormLinearPublic {
	_, g, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		panic(err)
	}

	gvec := make([]*bn256.G1, nLen)
	for i := range gvec {
		if _, gvec[i], err = bn256.RandomG1(rand.Reader); err != nil {
			panic(err)
		}
	}

	hvec := make([]*bn256.G1, lLen)
	for i := range hvec {
		if _, hvec[i], err = bn256.RandomG1(rand.Reader); err != nil {
			panic(err)
		}
	}

	c := make([]*big.Int, lLen)
	for i := range c {
		if c[i], err = rand.Int(rand.Reader, bn256.Order); err != nil {
			panic(err)
		}
	}

	ro, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		panic(err)
	}

	return &WeightNormLinearPublic{
		G:    g,
		GVec: gvec,
		HVec: hvec,
		C:    c,
		Ro:   ro,
		Mu:   mul(ro, ro),
	}
}
