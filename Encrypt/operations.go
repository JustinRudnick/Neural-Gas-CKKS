package encrypt

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"gonum.org/v1/gonum/mat"
)

/*
Reduces level by 1.
*/
func MulCoeff(
	koeff float64,
	encVec *rlwe.Ciphertext,
	ecd *ckks.Encoder,
	enc *rlwe.Encryptor,
	eval *ckks.Evaluator,
	params *ckks.Parameters,
	bootstrapper *bootstrapping.Evaluator,
) (ct *rlwe.Ciphertext, err error) {
	diff := encVec
	koeffVec := fillVec(koeff, diff.Slots())
	encKoeffVec, err := EncSample(koeffVec, ecd, enc, params) // epsilon * e^{-k/lambda}
	if err != nil {
		return nil, err
	}

	diff, encKoeffVec, err = EquateLevel(diff, encKoeffVec, bootstrapper, func(minLvl int) bool { return minLvl < 1 })
	if err != nil {
		return nil, err
	}

	if err = eval.MulRelin(diff, encKoeffVec, diff); err != nil { // epsilon * e^{-k/lambda} * (v - w_iOld)
		return nil, err
	}
	if err = eval.Rescale(diff, diff); err != nil {
		return nil, err
	}
	return diff, nil
}

func EquateLevel(ct0, ct1 *rlwe.Ciphertext, bootstrapper bootstrapping.Bootstrapper, bootstrap func(minLevel int) bool) (res0, res1 *rlwe.Ciphertext, err error) {
	if ct0 == nil {
		return nil, nil, fmt.Errorf("ct0 is nil")
	}
	if ct1 == nil {
		return nil, nil, fmt.Errorf("ct1 is nil")
	}

	minLevel := int(math.Min(float64(ct0.Level()), float64(ct1.Level())))
	c0 := ct0
	c1 := ct1

	if bootstrap(minLevel) {
		bootstrapped, err := bootstrapper.BootstrapMany([]rlwe.Ciphertext{*ct0, *ct1})
		if err != nil {
			return nil, nil, err
		}
		c0 = &bootstrapped[0]
		c1 = &bootstrapped[1]
	}

	// if c0.Level() != int(minLevel) {
	// 	c0.Resize(c0.Degree(), int(minLevel))
	// } else if ct1.Level() != int(minLevel) {
	// 	c1.Resize(c1.Degree(), int(minLevel))
	// }

	return c0, c1, nil

}

func AssureLevel(ct *rlwe.Ciphertext, bootstrapper bootstrapping.Bootstrapper, performBootstrap func(ctLevel int) bool) (res *rlwe.Ciphertext, err error) {
	var bootstrapped *rlwe.Ciphertext
	if performBootstrap(ct.Level()) {
		bootstrapped, err = bootstrapper.Bootstrap(ct)
		if err != nil {
			return nil, err
		}
		return bootstrapped, nil
	}
	return ct, nil
}

// fills a vector with
func fillVec(component float64, dimensions int) *mat.VecDense {
	array := make([]float64, dimensions)
	for i := range dimensions {
		array[i] = component
	}
	return mat.NewVecDense(dimensions, array)
}

/*
Scales up the input by bitScale bits,
cleans up the precision and scales the input down again.

reduces the ciphertext level by 2.
*/
func CleanUpMod1(ct *rlwe.Ciphertext, bitScale int, eval *ckks.Evaluator, mod1eval *mod1.Evaluator) (err error) {
	err = eval.MulRelin(ct, 1<<bitScale, ct)
	if err != nil {
		return fmt.Errorf("Clean up failed: %s", err.Error())
	}
	err = eval.Rescale(ct, ct)
	if err != nil {
		return fmt.Errorf("Clean up failed: %s", err.Error())
	}

	mod, err := mod1eval.EvaluateNew(ct)
	if err != nil {
		return fmt.Errorf("Clean up failed: %s", err.Error())
	}
	err = eval.Sub(ct, mod, ct)
	if err != nil {
		return fmt.Errorf("Clean up failed: %s", err.Error())
	}

	err = eval.MulRelin(ct, float64(1)/float64(int(1)<<bitScale), ct)
	if err != nil {
		return fmt.Errorf("Clean up failed: %s", err.Error())
	}
	err = eval.Rescale(ct, ct)
	if err != nil {
		return fmt.Errorf("Clean up failed: %s", err.Error())
	}
	return
}

/*
Scales up the input by bitScale bits,
cleans up the precision and scales down the input again.

returns a ciphertext with reduced level by 2.
*/
func CleanUpMod1New(ct *rlwe.Ciphertext, bitScale int, eval *ckks.Evaluator, mod1eval *mod1.Evaluator) (res *rlwe.Ciphertext, err error) {
	ct = ckks.NewCiphertext(*eval.GetParameters(), ct.Degree(), ct.Level())
	return ct, CleanUpMod1(ct, bitScale, eval, mod1eval)
}
