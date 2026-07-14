package encrypt

import (
	util "NeuralGasCKKS/Util"

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
func SortElements(small, large *util.RankedPrototype, identity *rlwe.Ciphertext, eval *ckks.Evaluator, cmp *comparison.Evaluator) (err error) {

	diff, err := eval.SubNew(small.Distance, large.Distance)
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

	small.Prototype, err = min(small.Prototype, large.Prototype, step, invStep, eval)
	if err != nil {
		return err
	}
	small.Distance, err = min(small.Distance, large.Distance, step, invStep, eval)
	if err != nil {
		return err
	}

	large.Prototype, err = max(small.Prototype, large.Prototype, step, invStep, eval)
	if err != nil {
		return err
	}
	large.Distance, err = max(small.Distance, large.Distance, step, invStep, eval)

	return err
}

/*
--- Variables ---

[in, out] array ...an array of [rlwe.Ciphertext]s to sort

[in] sortingElements ...the amount of items to sort before interrupting

--- Description ---

The [util.RankedPrototype]s themselves are not swapped, but their contents.
*/
// TODO
func BubbleSort(
	array []*util.RankedPrototype,
	sortingElements int,
	ecd *ckks.Encoder,
	enc *rlwe.Encryptor,
	params *ckks.Parameters,
	eval *ckks.Evaluator,
	cmp *comparison.Evaluator) (err error) {

	identity, err := IdentityCipher(array[0].Prototype.Slots(), ecd, enc, params)
	if err != nil {
		return err
	}

	for i := 0; i < sortingElements; i++ {
		for j := len(array) - 2; j >= i; j-- {
			err = SortElements(array[j], array[j+1], identity, eval, cmp)
			if err != nil {
				break
			}
		}
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

/*
--- Variables ---

[in] x0, x1 ...ciphertexts to calculate max

[in] step ...step(x0 - x1) using Step function of [comparison.Evaluator]

[in] invStep ...1 - step

[in] eval ...evaluator to perform computations

--- Returns ---

The smooth maximum of the [rlwe.Ciphertext]s x0, x1
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
