package noise

import "fmt"

type NoiseBound struct {
	N int //slots of ciphertext

}

type Bound float64

// func Mf(poly bignum.Polynomial, ct *rlwe.Ciphertext){
// 	ct.MetaData.PlaintextMetaData.
// }

/*
Lemma 3, https://eprint.iacr.org/2016/421 (Homomorphic Encryption for Arithmetic of Approximate Numbers)
*/
func AddUpperBound(b1 Bound, b2 Bound) Bound {
	return b1 + b2
}

func SubUpperBound(b1 Bound, b2 Bound) Bound {
	return b1 + b2
}

// input: canonical message and error bound
func EvalPolyUpperBound(msgBound, errBound float64, ciphertextMaxLevel int, polyCoeffs []float64) (newMsgBound, newErrBound float64, err error) {
	beta0 := float64(errBound) / float64(msgBound)

	Mf, err := MfUpperBound(float64(errBound), polyCoeffs)
	if err != nil {
		return 0, 0, fmt.Errorf("could not compute polynomial upper bound: %s", err.Error())
	}

	newMsgBound = Mf
	newErrBound = Mf * BetaDUpperBound(len(polyCoeffs), beta0, BetaAsteriskUpperBound(ciphertextMaxLevel))

	return newMsgBound, newErrBound, nil

}

/*
Section 4, https://eprint.iacr.org/2016/421 (Homomorphic Encryption for Arithmetic of Approximate Numbers)
*/
func MulRSUpperBound(msgBound1, errBound1, msgBound2, errBound2 float64, ciphertextMaxLevel int) (newMsgBound, newErrBound float64) {
	beta1, beta2 := errBound1/msgBound1, errBound2/msgBound2
	newBound := msgBound1 * msgBound2
	return newBound, (beta1 + beta2 + BetaAsteriskUpperBound(ciphertextMaxLevel)) * newBound
}
