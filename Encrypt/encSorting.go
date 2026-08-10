package encrypt

import (
	util "NeuralGasCKKS/Util"
	"fmt"
	"log/slog"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/comparison"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

/*
--- Variables ---

[in, out] small ...a [util.RankedPrototype] containing the prototype of shorter distance after evaluating this function

[in, out] large ...a [util.RankedPrototype] containing the prototype of larger distance after evaluating this function

[in] identity ...an identity ciphertext (encrypted identity vector)

[in] eval ...evaluator to perform computations

[in] cmp ...evalurator to perform comparison

--- Description ---

It swaps the prototypes and distances within the [util.RankedPrototype]s, if necessary. This operation lowers the ciphertexts levels by 1.
*/
func SortElements(
	small, large *util.RankedPrototype,
	identity *rlwe.Ciphertext,
	eval *ckks.Evaluator,
	cmp *comparison.Evaluator,
	btp *bootstrapping.Evaluator,
) (err error) {
	if small == nil {
		return fmt.Errorf("<small> is nil")
	}
	if large == nil {
		return fmt.Errorf("<large> is nil")
	}

	sProto, lProto, err := EquateLevel(small.Prototype, large.Prototype, btp, func(minLvl int) bool { return minLvl < 2 })
	if err != nil {
		return fmt.Errorf("EquateLevel failed: %s", err.Error())
	}

	sDist, lDist, err := EquateLevel(small.Distance, large.Distance, btp, func(minLvl int) bool { return minLvl < 2 })
	if err != nil {
		return fmt.Errorf("EquateLevel failed: %s", err.Error())
	}

	diff, err := eval.SubNew(sDist, lDist)
	if err != nil {
		return err
	}

	step, err := cmp.Step(diff)
	if err != nil {
		return fmt.Errorf("Evaluating step failed: %s", err.Error())
	}

	invStep, err := eval.SubNew(identity, step)
	if err != nil {
		return err
	}

	smallProto, err := min(sProto, lProto, step, invStep, eval)
	if err != nil {
		return fmt.Errorf("min function for smallProto failed: %s", err.Error())
	}
	smallDist, err := min(sDist, lDist, step, invStep, eval)
	if err != nil {
		return fmt.Errorf("min function for smallDist failed: %s", err.Error())
	}

	largeProto, err := max(sProto, lProto, step, invStep, eval)
	if err != nil {
		return fmt.Errorf("max function for largeProto failed: %s", err.Error())
	}
	largeDist, err := max(sDist, lDist, step, invStep, eval)
	if err != nil {
		return fmt.Errorf("max function for largeDist failed: %s", err.Error())
	}

	small.Prototype = smallProto
	small.Distance = smallDist

	large.Prototype = largeProto
	large.Distance = largeDist

	return nil
}

/*
--- Variables ---

[in, out] array ...an array of [rlwe.Ciphertext]s to sort

[in] sortingElements ...the amount of items to sort before interrupting

--- Description ---

The [util.RankedPrototype]s themselves are not swapped, but their contents.

	Decreases the level of the (most) cyphertexts by 2 per loop. Looping <ng.optimizingPrototypeCount> times.
*/
func BubbleSort(
	array []*util.RankedPrototype,
	sortingElements int,
	ecd *ckks.Encoder,
	enc *rlwe.Encryptor,
	params *ckks.Parameters,
	eval *ckks.Evaluator,
	cmp *comparison.Evaluator,
	bootstrapper *bootstrapping.Evaluator,
	logger *slog.Logger,
) (err error) {
	if logger != nil {
		logger.Info("Starting bubble sort.")
	}

	identity, err := IdentityCipherInstance(array[0].Prototype.Slots())
	if err != nil {
		if logger != nil {
			logger.Info("Identity Ciphertext could not be initialized.")
		}
		return err
	}

	for i := 0; i < sortingElements; i++ {
		for j := len(array) - 2; j >= i; j-- {
			if logger != nil {
				logger.Info(fmt.Sprintf("Comparing indexes: %d and %d", j, j+1))
			}
			err = SortElements(array[j], array[j+1], identity, eval, cmp, bootstrapper)
			if err != nil {
				if logger != nil {
					logger.Error(fmt.Sprintf("Sorting elements raised an error: %s", err.Error()))
				}
				break
			}
		}
	}

	if logger != nil {
		logger.Info("Ending bubble sort.")
	}
	return err
}

// WORKS tested
func MaxTest(x0, x1, step, invStep *rlwe.Ciphertext, eval *ckks.Evaluator) (smoothMax *rlwe.Ciphertext, err error) {
	return max(x0, x1, step, invStep, eval)
}

// WORKS tested
func MinTest(x0, x1, step, invStep *rlwe.Ciphertext, eval *ckks.Evaluator) (smoothMax *rlwe.Ciphertext, err error) {
	return min(x0, x1, step, invStep, eval)
}

/*
--- Variables ---

[in] x0, x1 ...ciphertexts to calculate max

[in] step ...step(x0 - x1) using Step function of [comparison.Evaluator]

[in] invStep ...1 - step(x0 - x1)

[in] eval ...evaluator to perform computations

--- Returns ---

The smooth maximum of the [rlwe.Ciphertext]s x0, x1

	Level of the smoothMax is 1 less than the input ciphertexts
*/
func max(x0, x1, step, invStep *rlwe.Ciphertext, eval *ckks.Evaluator) (smoothMax *rlwe.Ciphertext, err error) {
	prod0, err := eval.MulRelinNew(x0, step)
	if err != nil {
		return nil, err
	}
	err = eval.Rescale(prod0, prod0)
	if err != nil {
		return nil, err
	}

	prod1, err := eval.MulRelinNew(x1, invStep)
	if err != nil {
		return nil, err
	}
	err = eval.Rescale(prod1, prod1)
	if err != nil {
		return nil, err
	}

	err = eval.Add(prod0, prod1, prod0)
	if err != nil {
		return nil, err
	}

	return prod0, nil
}

/*
--- Variables ---

[in] x0, x1 ...ciphertexts to calculate min

[in] step ...step(x0 - x1) using Step function of [comparison.Evaluator]

[in] invStep ...1 - step(x0 - x1)

[in] eval ...evaluator to perform computations

--- Returns ---

The smooth minimum of the [rlwe.Ciphertext]s x0, x1

	Level of the smoothMin is 1 less than the input ciphertexts
*/
func min(x0, x1, step, invStep *rlwe.Ciphertext, eval *ckks.Evaluator) (smoothMin *rlwe.Ciphertext, err error) {
	return max(x0, x1, invStep, step, eval)
}

func CleanIntMod1(ct *rlwe.Ciphertext, evk *rlwe.EvaluationKey, mod1eval *mod1.Evaluator) (err error) {
	return mod1eval.Evaluator.ApplyEvaluationKey(ct, evk, ct)
}

func CleanIntMod1New(ct *rlwe.Ciphertext, evk *rlwe.EvaluationKey, eval *ckks.Evaluator, mod1eval *mod1.Evaluator) (res *rlwe.Ciphertext, err error) {
	ct = ckks.NewCiphertext(*eval.GetParameters(), ct.Degree(), ct.Level())
	return ct, CleanIntMod1(ct, evk, mod1eval)
}
