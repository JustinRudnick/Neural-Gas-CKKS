package neuralgas

import (
	encrypt "NeuralGasCKKS/Encrypt"
	parallelize "NeuralGasCKKS/Parallelize"
	plotting "NeuralGasCKKS/Plotting"
	util "NeuralGasCKKS/Util"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/comparison"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"gonum.org/v1/gonum/mat"
)

type EncParams struct {
	Ecd          *ckks.Encoder
	Enc          *rlwe.Encryptor
	Eval         *ckks.Evaluator
	Params       *ckks.Parameters
	Cmp          *comparison.Evaluator
	Bootstrapper *bootstrapping.Evaluator

	Dec *rlwe.Decryptor //TODO delete
}

type Params struct {
	LearningRate_initial     float64
	LearningRate_final       float64
	InnerTemperature_initial float64
	InnerTemperature_final   float64
}

type NeuralGas struct {
	samples                  []*rlwe.Ciphertext
	prototypes               []*rlwe.Ciphertext
	optimizingPrototypeCount uint // amount of nearest prototypes to a sample to optimize with step()
	randomizer               *rand.Rand

	constants Params
	EncParams *EncParams
	logger    *slog.Logger
	isLogged  bool
}

// returns a neural gas algorithm with normalized generated prototypes
// input dataset components must be normalized to interval [0, 1]
func NewNorm(
	dataset []*rlwe.Ciphertext,
	dimensions uint,
	prototypeCount uint,
	randomizer *rand.Rand,
	params Params,
	encParams EncParams,
	maxCores int,
	logger *slog.Logger,
) (ng *NeuralGas, err error) {

	prototypes := make([]*mat.VecDense, prototypeCount)

	for i := range prototypeCount {
		prototype := make([]float64, dimensions)
		for j := range dimensions {
			prototype[j] = randomizer.Float64()
		}
		prototypes[i] = mat.NewVecDense(int(dimensions), prototype)
	}

	encPrototypes, err := encrypt.EncSamplesThreaded(prototypes, encParams.Ecd, encParams.Enc, encParams.Params, maxCores, logger)
	if err != nil {
		return nil, err
	}

	isLogged := logger != nil
	if isLogged {
		logger.Info("New normalized [NeuralGas] object has been created.")
	}

	return &NeuralGas{
		samples:                  dataset,
		prototypes:               encPrototypes,
		optimizingPrototypeCount: prototypeCount,
		randomizer:               randomizer,
		constants:                params,
		EncParams:                &encParams,
		logger:                   logger,
		isLogged:                 isLogged}, nil
}

func NewRankedPrototype(prototype *rlwe.Ciphertext, distance *rlwe.Ciphertext) *util.RankedPrototype {
	return &util.RankedPrototype{Prototype: prototype, Distance: distance}
}

/*
This function evaluates a learning step on the passed <rankedPrototypes> of neural gas algorithm.
The learning step function will only be applied for the
<ng.optimizingPrototypeCount> closest <rankedPrototypes> to the passed <sample> using euclidean distance.
This function destroys the identity of the <rankdedPrototypes> within the slice.
*/
func (ng *NeuralGas) step(
	sample *rlwe.Ciphertext,
	rankedPrototypes []*util.RankedPrototype,
	iteration int,
	maxIterations int,
	maxCores int) (err error) {
	eval := ng.EncParams.Eval
	ecd := ng.EncParams.Ecd
	enc := ng.EncParams.Enc
	params := ng.EncParams.Params
	logger := ng.logger
	bootstrapper := ng.EncParams.Bootstrapper
	cmp := ng.EncParams.Cmp

	var errors chan error = make(chan error, 1)

	parallelize.MultiThread(
		sample,
		rankedPrototypes,
		maxCores,
		func(sample *rlwe.Ciphertext, rankedPrototypes []*util.RankedPrototype, startIdx int, wg *sync.WaitGroup) {
			var err error
			defer wg.Done()
			for i := range rankedPrototypes { // calculate distances from prototypes to the sample
				rankedPrototypes[i].Distance, err = DistanceSq(sample, rankedPrototypes[i].Prototype, ng.EncParams)
				if err != nil {
					select {
					case errors <- err: // non blocking
					default:
					}
					if ng.isLogged {
						totalIdx := startIdx + i
						logger.Error(fmt.Sprintf("Calculating distance failed for prototype idx: %d at iteration %d", totalIdx, iteration))
					}
				}
			}
		})

	select {
	case err = <-errors: // non blocking
		return fmt.Errorf("Calculating distances (threaded) in step function failed:\n\t%w", err)
	default:
	}

	/*
		It exists a sorting algoritm, that takes two input ciphertexts A[0] and A[1] and returns B[0] (smaller) and B[1] (bigger)
		with same pt for the input and equivalent output according to Section 4.1 of the paper [https://ieeexplore.ieee.org/document/7937936] (#1 Src 9)
	*/
	err = encrypt.BubbleSort(rankedPrototypes, int(ng.optimizingPrototypeCount), ecd, enc, params, eval, cmp, bootstrapper, nil)
	if err != nil {
		return err
	}

	lambda := ng.InnerTemperature(iteration, maxIterations)
	epsilon := ng.StepWidth(iteration, maxIterations)

	parallelize.MultiThread(
		sample,
		rankedPrototypes[:ng.optimizingPrototypeCount],
		maxCores,
		func(sample *rlwe.Ciphertext, rankedPrototypes []*util.RankedPrototype, originalOffset int, wg *sync.WaitGroup) {
			var err error
			defer wg.Done()

			for off := range rankedPrototypes {
				totalIdx := originalOffset + off
				rank := originalOffset + off

				exp := math.Exp(-float64(rank) / lambda) // e^{-k/lambda}
				koeff := epsilon * exp

				var diff *rlwe.Ciphertext
				diff, err = eval.SubNew(sample, rankedPrototypes[off].Prototype) // (v - w_iOld)
				if err != nil {
					if logger != nil {
						logger.Error(fmt.Sprintf("Calculating difference vector failed for prototype idx: %d at iteration %d", totalIdx, iteration))
					}
					select {
					case errors <- err: // non blocking
						return
					default:
					}
				}

				diff, err = encrypt.MulCoeff(koeff, diff, ecd, enc, eval, params, bootstrapper)
				if err != nil {
					if logger != nil {
						logger.Error(fmt.Sprintf("Multiplying coefficient to difference vector failed for prototype idx: %d at iteration %d", totalIdx, iteration))
					}
					select {
					case errors <- err: // non blocking
						return
					default:
					}
				}

				if err := eval.Add(rankedPrototypes[off].Prototype, diff, rankedPrototypes[off].Prototype); err != nil { // w_iOld + epsilon * e^{-k/lambda} * (v - w_iOld)
					if logger != nil {
						logger.Error(fmt.Sprintf("Evaluation adaption step failed for prototype idx: %d at iteration %d", totalIdx, iteration))
					}
					select {
					case errors <- err: // non blocking
						return
					default:
					}
				}

			}
		})

	select {
	case err = <-errors: // non blocking
		return err
	default:
		return nil
	}
}

/*
Trains the prototypes of this [NeuralGas] for the amount of <epochs> using <maxCores> threads.
*/
func (ng *NeuralGas) Train(epochs uint, maxCores uint) (err error) {
	initialT := time.Now()
	if ng.isLogged {
		ng.logger.Info(fmt.Sprintf("Begin training for %d epoch(s) using %d threads.", epochs, maxCores))
	}

	iteration := 0
	totalIterations := int(epochs) * len(ng.samples)
	for epoch := range epochs {
		ng.ShuffleSamples()

		prototypeCount := len(ng.prototypes)
		rankedPrototypes := make([]*util.RankedPrototype, prototypeCount)
		for i := range prototypeCount {
			rankedPrototypes[i] = &util.RankedPrototype{Prototype: ng.prototypes[i], Distance: nil}
		}

		for _, sample := range ng.samples {
			err = ng.step(sample, rankedPrototypes, iteration, totalIterations, int(maxCores))
			if err != nil {
				return err
			}

			for i := range rankedPrototypes {
				ng.prototypes[i] = rankedPrototypes[i].Prototype
			}

			iteration++
		}

		if ng.isLogged && (epoch+1)%(epochs/uint(math.Min(float64(epochs), float64(10)))) == 0 {
			ng.logger.Info(fmt.Sprintf("---------------------- EPOCH %d / %d -----------------------", epoch+1, epochs))
		}
	}

	if ng.isLogged {
		ng.logger.Info(fmt.Sprintf("Training of %d epoch(s) in %f sec.", epochs, float64(time.Since(initialT))/float64(time.Second)))
	}

	return nil

}

func (ng *NeuralGas) TrainPlots(epochs uint, maxCores uint, filenames string, plotEpochs []int) (err error) {
	initialT := time.Now()
	if ng.isLogged {
		ng.logger.Info(fmt.Sprintf("Begin training for %d epoch(s) using %d threads.", epochs, maxCores))
	}

	ecd := ng.EncParams.Ecd
	dec := ng.EncParams.Dec
	logger := ng.logger

	iteration := 0
	totalIterations := int(epochs) * len(ng.samples)
	for epoch := range epochs {
		ng.ShuffleSamples()

		prototypeCount := len(ng.prototypes)
		rankedPrototypes := make([]*util.RankedPrototype, prototypeCount)
		for i := range prototypeCount {
			rankedPrototypes[i] = &util.RankedPrototype{Prototype: ng.prototypes[i], Distance: nil}
		}

		for _, sample := range ng.samples {
			err = ng.step(sample, rankedPrototypes, iteration, totalIterations, int(maxCores))
			if err != nil {
				return err
			}

			for i := range rankedPrototypes {
				ng.prototypes[i] = rankedPrototypes[i].Prototype
			}

			iteration++
		}

		plotEpoch := false
		for _, ep := range plotEpochs {
			if ep == int(epoch)+1 {
				plotEpoch = true
				break
			}
		}

		if plotEpoch {
			msgs, err := encrypt.DecSamples(ng.Prototypes(), ecd, dec, logger)
			if err != nil {
				return err
			}

			plotting.Plot2D(msgs, fmt.Sprintf("%d epoch(s), %d prototypes", epoch+1, prototypeCount), fmt.Sprintf("%s%d", filenames, epoch+1))
		}

		if ng.isLogged && (epoch+1)%(epochs/uint(math.Min(float64(epochs), float64(10)))) == 0 {
			ng.logger.Info(fmt.Sprintf("---------------------- EPOCH %d / %d -----------------------", epoch+1, epochs))
		}
	}

	if ng.isLogged {
		ng.logger.Info(fmt.Sprintf("Training of %d epoch(s) in %f sec.", epochs, float64(time.Since(initialT))/float64(time.Second)))
	}

	return nil

}

//###################### Getter functions ##############################################################

func (ng *NeuralGas) StepWidth(iteration int, maxIterations int) float64 {
	return calculation(ng.constants.LearningRate_initial, ng.constants.LearningRate_final, iteration, maxIterations)
}

func (ng *NeuralGas) InnerTemperature(iteration int, maxIterations int) float64 {
	return calculation(ng.constants.InnerTemperature_initial, ng.constants.InnerTemperature_final, iteration, maxIterations)
}

func (ng NeuralGas) Prototypes() []*rlwe.Ciphertext {
	return ng.prototypes
}

func (ng NeuralGas) Samples() []*rlwe.Ciphertext {
	return ng.samples
}

func (ng NeuralGas) OptimizingPrototypeCount() int {
	return int(ng.optimizingPrototypeCount)
}

func (ng NeuralGas) SetOptimizingPrototypeCount(new uint) {
	ng.optimizingPrototypeCount = new
}

//###################### Helper functions ####################################################

// returns gI * (gF/gI)^(t/t_max)
func calculation(gI float64, gF float64, t int, tMax int) float64 {
	return gI * math.Pow(gF/gI, float64(t)/float64(tMax))
}

// fills a vector with
func fillVec(component float64, dimensions int) *mat.VecDense {
	array := make([]float64, dimensions)
	for i := range dimensions {
		array[i] = component
	}
	return mat.NewVecDense(dimensions, array)
}

func (ng NeuralGas) swap(i int, j int) {
	ng.samples[i], ng.samples[j] = ng.samples[j], ng.samples[i]
}

// returns the squared euclidian distance of the passed vectors
//
//	The level of ciphertext distance is 1 level lower, than the levels of the ciphertexts v1 and v2.
func DistanceSq(v1 *rlwe.Ciphertext, v2 *rlwe.Ciphertext, encParams *EncParams) (dist *rlwe.Ciphertext, err error) {
	ecd := encParams.Ecd
	enc := encParams.Enc
	eval := encParams.Eval
	params := encParams.Params
	btp := encParams.Bootstrapper

	c0, c1, err := encrypt.EquateLevel(v1, v2, btp, func(minLevel int) bool { return minLevel < 2 })
	if err != nil {
		return nil, fmt.Errorf("DistanceSq(): EquateLevel failed with: %w", err)
	}

	//delta
	sum, err := eval.SubNew(c0, c1)
	if err != nil {
		return nil, err
	}

	//squared
	if err := eval.MulRelin(sum, sum, sum); err != nil {
		return nil, err
	}

	if err := eval.Rescale(sum, sum); err != nil {
		return nil, err
	}

	//summed
	if err := eval.InnerSum(sum, 1, sum.Slots(), sum); err != nil {
		return nil, err
	}

	sum, err = encrypt.MulCoeff(float64(1)/float64(sum.Slots()), sum, ecd, enc, eval, params, btp) //eval.MulRelinNew(sum, float64(1)/float64(sum.Slots()))
	if err != nil {
		return nil, err
	}

	return sum, nil
}

// Shuffle pseudo-randomizes the order of elements.
// n is the number of elements. Shuffle panics if n < 0.
// swap swaps the elements with indexes i and j.
//
// A modification of [rand.Shuffle] to set the pseudo-randomizer
func Shuffle(n int, randomizer *rand.Rand, swap func(i, j int)) {
	if n < 0 {
		panic("invalid argument to Shuffle")
	}

	// Fisher-Yates shuffle: https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
	// Shuffle really ought not be called with n that doesn't fit in 32 bits.
	// Not only will it take a very long time, but with 2³¹! possible permutations,
	// there's no way that any PRNG can have a big enough internal state to
	// generate even a minuscule percentage of the possible permutations.
	// Nevertheless, the right API signature accepts an int n, so handle it as best we can.
	i := n - 1
	for ; i > 1<<31-1-1; i-- {
		j := int(randomizer.Int63n(int64(i + 1)))
		swap(i, j)
	}
	for ; i > 0; i-- {
		j := int(randomizer.Int31n(int32(i + 1)))
		swap(i, j)
	}
}

// ShuffleSamples pseudo-randomizes the order of ng.samples using the randomizer of ng.
//
// A modification of [rand.Shuffle] to set the pseudo-randomizer
func (ng *NeuralGas) ShuffleSamples() {
	Shuffle(len(ng.samples), ng.randomizer, ng.swap)
}
