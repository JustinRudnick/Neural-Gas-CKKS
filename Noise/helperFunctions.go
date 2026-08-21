package noise

import (
	util "NeuralGasCKKS/Util"
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

/*
returns the canonical infinity norm of the passed vector
*/
func CanInfNorm[T util.Number](values []T, enc *ckks.Encoder) (norm float64, err error) {
	params := enc.GetParameters().Parameters
	pt := rlwe.NewPlaintext(params, params.MaxLevel())

	err = enc.Encode(values, pt)
	if err != nil {
		return math.NaN(), err
	}

	max, err := util.Max(util.Abs(pt.Value.Coeffs[0]))
	if err != nil {
		return math.NaN(), fmt.Errorf("Cannot compute canonical infinity norm: %s", err.Error())
	}

	return float64(max), nil

}

/*
returns the infinity norm of the passed vector
*/
func InfNorm[T util.Number](values []T) (norm T, err error) {
	return util.Max(util.Abs(values))
}

/*
Theorem 1 of https://eprint.iacr.org/2022/162 (On precision loss in approximate homomorphic encryption)

Uses unencoded values as input.
*/
func CanInfNormUpperBound[T util.Number](values []T) (norm float64, err error) {
	In := I(len(values), 1)
	InfN, err := InfNorm(values)
	if err != nil {
		return math.NaN(), fmt.Errorf("Could not compute upper bound: %s", err.Error())
	}

	return math.Sqrt(In*In+1) * float64(InfN), nil

}

/*
I-function from https://eprint.iacr.org/2022/162 (On precision loss in approximate homomorphic encryption)

I(N) == I(N, 1) - Lemma 3
*/
func I(N int, j int) float64 {
	var sum float64 = 0
	var factor float64 = float64(j) * math.Pi / float64(N)

	for k := range N {
		sum += math.Abs(math.Sin(factor * float64(k)))
	}

	return sum
}

/*
helper function from Lemma 7, https://eprint.iacr.org/2016/421 (Homomorphic Encryption for Arithmetic of Approximate Numbers)
*/
func BetaDUpperBound(degree int, beta0, betaAsterisk float64) float64 {
	return float64(degree)*beta0 + (float64(degree)-1)*betaAsterisk
}

/*
helper function from section 4.1, https://eprint.iacr.org/2016/421 (Homomorphic Encryption for Arithmetic of Approximate Numbers)
*/
func BetaAsteriskUpperBound(ciphertextMaxLevel int) float64 {
	return 1 / math.Pow(2, float64(ciphertextMaxLevel)+2)
}

/*
helper function from Lemma 7, https://eprint.iacr.org/2016/421 (Homomorphic Encryption for Arithmetic of Approximate Numbers)
*/
func MfUpperBound(bound float64, poly []float64) (Mf float64, err error) {
	var sum float64 = 0
	var add float64

	for d := range len(poly) {
		add, err = CanInfNormUpperBound([]float64{poly[d]})
		if err != nil {
			return math.NaN(), fmt.Errorf("could not compute Mf upper bound: %s", err.Error())
		}

		sum += add
	}

	return bound * sum, nil
}
