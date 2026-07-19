package encrypt

import (
	globals "NeuralGasCKKS/Globals"
	util "NeuralGasCKKS/Util"
	"fmt"
	"log/slog"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/comparison"
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
		return err
	}

	sDist, lDist, err := EquateLevel(small.Distance, large.Distance, btp, func(minLvl int) bool { return minLvl < 2 })
	if err != nil {
		return err
	}

	//-------------------------------------- TEST --------------------------------------------------------------------
	// dec := globals.DECRYPTOR
	// ecd := globals.ECD
	// logger := globals.LOGGER

	// if dec != nil {
	// 	small, err := DecSample(sProto, ecd, dec)
	// 	large, err := DecSample(lProto, ecd, dec)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	if logger != nil {
	// 		logger.Info(fmt.Sprintf("Comparing: [%f, %f] with [%f, %f]",
	// 			small.RawVector().Data[0],
	// 			small.RawVector().Data[1],
	// 			large.RawVector().Data[0],
	// 			large.RawVector().Data[1],
	// 		))
	// 	}
	// }
	//------------------------------------ TEST END --------------------------------------------------------------------

	diff, err := eval.SubNew(sDist, lDist)
	if err != nil {
		return err
	}

	step, err := cmp.Step(diff)
	if err != nil {
		return err
	}

	invStep, err := eval.SubNew(identity, step)
	if err != nil {
		return err
	}

	// //-------------------------------------- TEST --------------------------------------------------------------------
	// if dec != nil {
	// 	small, err := DecSample(step, ecd, dec)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	if logger != nil {
	// 		logger.Info(fmt.Sprintf("Step: [%v]",
	// 			small.RawVector().Data,
	// 		))
	// 	}
	// }
	// //------------------------------------ TEST END --------------------------------------------------------------------

	smallProto, err := min(sProto, lProto, step, invStep, eval)
	if err != nil {
		return err
	}
	smallDist, err := min(sDist, lDist, step, invStep, eval)
	if err != nil {
		return err
	}

	large.Prototype, err = max(sProto, lProto, step, invStep, eval)
	if err != nil {
		return err
	}
	large.Distance, err = max(sDist, lDist, step, invStep, eval)

	small.Prototype = smallProto
	small.Distance = smallDist

	//-------------------------------------- TEST --------------------------------------------------------------------
	// if dec != nil {
	// 	small, err := DecSample(small.Prototype, ecd, dec)
	// 	large, err := DecSample(large.Prototype, ecd, dec)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	if logger != nil {
	// 		logger.Info(fmt.Sprintf("After swapping: [%f, %f] with [%f, %f]",
	// 			small.RawVector().Data[0],
	// 			small.RawVector().Data[1],
	// 			large.RawVector().Data[0],
	// 			large.RawVector().Data[1],
	// 		))
	// 	}
	// }
	//------------------------------------ TEST END --------------------------------------------------------------------

	return err
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

	identity, err := IdentityCipher(array[0].Prototype.Slots(), ecd, enc, params)
	if err != nil {
		if logger != nil {
			logger.Info("Identity Ciphertext could not be initialized.")
		}
		return err
	}

	//-------------------------------------- TEST --------------------------------------------------------------------
	dec := globals.DECRYPTOR
	for _, proto := range array {

		if dec != nil {
			adaption, err := DecSample(proto.Prototype, ecd, dec)
			if err != nil {
				return err
			}
			if logger != nil {
				logger.Info(fmt.Sprintf("Pre-bubbling Prototype: [%f, %f]", adaption.RawVector().Data[0], adaption.RawVector().Data[1]))
			}
		}
	}
	//------------------------------------ TEST END --------------------------------------------------------------------

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
			// //-------------------------------------- TEST --------------------------------------------------------------------
			// for _, proto := range array {

			// 	if dec != nil {
			// 		adaption, err := DecSample(proto.Prototype, ecd, dec)
			// 		if err != nil {
			// 			return err
			// 		}
			// 		if logger != nil {
			// 			logger.Info(fmt.Sprintf("In-bubbling Prototype: [%f, %f]", adaption.RawVector().Data[0], adaption.RawVector().Data[1]))
			// 		}
			// 	}
			// }
			// //------------------------------------ TEST END --------------------------------------------------------------------
		}
	}

	//-------------------------------------- TEST --------------------------------------------------------------------
	for _, proto := range array {

		if dec != nil {
			adaption, err := DecSample(proto.Prototype, ecd, dec)
			if err != nil {
				return err
			}
			if logger != nil {
				logger.Info(fmt.Sprintf("Post-bubbling Prototype: [%f, %f]", adaption.RawVector().Data[0], adaption.RawVector().Data[1]))
			}
		}
	}
	//------------------------------------ TEST END --------------------------------------------------------------------

	if logger != nil {
		logger.Info("Ending bubble sort.")
	}
	return err
}

/*
Returns a [rlwe.Ciphertext] that represents an encrypted identity vector of <slots> dimensions.
*/
func IdentityCipher(slots int, ecd *ckks.Encoder, enc *rlwe.Encryptor, params *ckks.Parameters) (identity *rlwe.Ciphertext, err error) {
	oneSlice := make([]float64, slots)
	for i := range oneSlice {
		oneSlice[i] = 1
	}
	var pt *rlwe.Plaintext = ckks.NewPlaintext(*params, params.MaxLevel())
	err = ecd.Encode(oneSlice, pt)
	if err != nil {
		return nil, err
	}
	identity, err = enc.EncryptNew(pt)
	if err != nil {
		return nil, err
	}

	return identity, nil
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

[in] invStep ...1 - step

[in] eval ...evaluator to perform computations

--- Returns ---

The smooth maximum of the [rlwe.Ciphertext]s x0, x1

	Level of the smoothMin is 1 less than the input ciphertexts
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

[in] invStep ...1 - step

[in] eval ...evaluator to perform computations

--- Returns ---

The smooth minimum of the [rlwe.Ciphertext]s x0, x1

	Level of the smoothMin is 1 less than the input ciphertexts
*/
func min(x0, x1, step, invStep *rlwe.Ciphertext, eval *ckks.Evaluator) (smoothMin *rlwe.Ciphertext, err error) {
	prod0, err := eval.MulRelinNew(x0, invStep)
	if err != nil {
		return nil, err
	}
	err = eval.Rescale(prod0, prod0)
	if err != nil {
		return nil, err
	}

	prod1, err := eval.MulRelinNew(x1, step)
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
