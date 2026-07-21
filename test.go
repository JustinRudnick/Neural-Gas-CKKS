package main

import (
	encrypt "NeuralGasCKKS/Encrypt"
	neuralgas "NeuralGasCKKS/NeuralGas"
	util "NeuralGasCKKS/Util"
	"fmt"
	"log/slog"
	"math/rand"
	"os"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/comparison"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/minimax"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils"
	"gonum.org/v1/gonum/mat"
)

func main() {

	var seed int64 = 22
	randomizer := rand.New(rand.NewSource(seed))

	var logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	maxCores := 8

	//------------------
	// CKKS Initialization
	//------------------

	var err error
	var params ckks.Parameters

	scalingFactor := 45
	logAccuracy := 10
	level := 20
	logQ := util.FillSlice(scalingFactor, level+1)
	logQ[0] += logAccuracy

	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:4, LogQP: 431.
	if params, err = ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN:            4,             // log2(ring degree)
			LogQ:            logQ,          // log2(primes Q) (ciphertext modulus)
			LogP:            []int{61},     // log2(primes P) (auxiliary modulus)
			LogDefaultScale: scalingFactor, // log2(scale)
			RingType:        ring.ConjugateInvariant,
		}); err != nil {
		panic(err)
	}

	btpParametersLit := bootstrapping.ParametersLiteral{
		LogN: utils.Pointy(params.LogN() + 1), // Same LogN as ckks params. (This is not required.)
		LogP: []int{61},                       // number of auxiliary primes \theta = 2kp + 1 p \in primes, k \in N used by the evaluation keys of the bootstrapping circuit, so that the size of LogQP  meets the security target.
		Xs:   params.Xs(),                     // specify the bootstrapping parameters' secret distribution. (Not necessary.)
	}

	btpParams, err := bootstrapping.NewParametersFromLiteral(params, btpParametersLit)
	if err != nil {
		panic(err)
	}

	kgen := rlwe.NewKeyGenerator(params)     // Key Generator
	sk := kgen.GenSecretKeyNew()             // Secret Key
	ecd := ckks.NewEncoder(params)           // Encoder
	enc := rlwe.NewEncryptor(params, sk)     // Encryptor
	dec := rlwe.NewDecryptor(params, sk)     // Decryptor
	rlk := kgen.GenRelinearizationKeyNew(sk) // Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)  // Evaluation Key Set with the Relinearization Key
	eval := ckks.NewEvaluator(params, evk)   // Evaluator

	slots := 1 << params.LogN()
	batches := 1
	terms := slots / batches //terms per batch
	eval = eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(batches, terms), sk)...))

	logger.Info("Generating bootstrapping keys...")
	btpk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		panic(err)
	}
	logger.Info("Bootstrapping keys generated.")

	var bootstrapper *bootstrapping.Evaluator
	if bootstrapper, err = bootstrapping.NewEvaluator(btpParams, btpk); err != nil {
		panic(err)
	}
	cmp := comparison.NewEvaluator(params, minimax.NewEvaluator(params, eval, bootstrapper))

	//------------------
	// Samples init
	//------------------

	sampleCount := 6 //1<<params.LogN()
	sampleDims := 2
	sampleSet := make([]*mat.VecDense, sampleCount)
	// fillDataset(sampleSet)
	sampleSet[0] = mat.NewVecDense(sampleDims, []float64{0.5, 0.5})
	sampleSet[1] = mat.NewVecDense(sampleDims, []float64{0.2, 0.2})
	sampleSet[2] = mat.NewVecDense(sampleDims, []float64{0.4, 0.4})
	sampleSet[3] = mat.NewVecDense(sampleDims, []float64{0.25, 0.25})
	sampleSet[4] = mat.NewVecDense(sampleDims, []float64{0.1, 0.1})
	sampleSet[5] = mat.NewVecDense(sampleDims, []float64{0.05, 0.05})

	// distances := make([]*mat.VecDense, sampleCount)
	// distances[0] = mat.NewVecDense(sampleDims, []float64{0.5})
	// distances[1] = mat.NewVecDense(sampleDims, []float64{0.2})
	// distances[2] = mat.NewVecDense(sampleDims, []float64{0.4})
	// distances[3] = mat.NewVecDense(sampleDims, []float64{0.25})
	// distances[4] = mat.NewVecDense(sampleDims, []float64{0.1})
	// distances[5] = mat.NewVecDense(sampleDims, []float64{0.05})

	zeroVec := mat.NewVecDense(sampleDims, nil)
	encZero, err := encrypt.EncSample(zeroVec, ecd, enc, &params)
	if err != nil {
		panic(err)
	}

	//------------------
	// Encoding & Encryption
	//------------------

	var encSamples []*rlwe.Ciphertext
	if encSamples, err = encrypt.EncSamplesThreaded(sampleSet, ecd, enc, &params, maxCores, logger); err != nil {
		panic(err)
	}

	var encDistances []*rlwe.Ciphertext = make([]*rlwe.Ciphertext, 6)
	for i := range encDistances {
		encDistances[i], err = neuralgas.DistanceSq(encZero, encSamples[i], &neuralgas.EncParams{
			Ecd:          ecd,
			Enc:          enc,
			Eval:         eval,
			Params:       &params,
			Cmp:          cmp,
			Bootstrapper: bootstrapper,
		})
		if err != nil {
			panic(err)
		}
	}

	// var coeff float64 = 0.03

	// for i := range encSamples {
	// 	encSamples[i], err = encrypt.MulCoeff(coeff, encSamples[i], ecd, enc, eval, &params, bootstrapper)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }

	//------------------
	// Decrypt & Print
	//------------------

	// decSamples, err := encrypt.DecSamplesThreaded(encSamples, ecd, dec, maxCores, logger)

	// arr := make([]float64, sampleDims)
	// for i := range arr {
	// 	arr[i] = coeff
	// }
	// mulVec := mat.NewVecDense(sampleDims, arr)

	// for i := range sampleSet {
	// 	sampleSet[i].MulElemVec(sampleSet[i], mulVec)
	// }

	// want := toFloatArr(sampleSet) //[][]float64{{0.05}, {0.1}, {0.2}, {0.25}, {0.4}, {0.5}} //toFloatArr(sampleSet)
	// have := toFloatArr(decSamples)

	// for i := range int(math.Min(10, float64(sampleCount))) {
	// 	printing.PrintSlots(want[i], have[i], sampleDims)
	// }

	//---------------------------------------------------------------------------------------------------------------------------------------------

	prototypeCount := 4

	paramsNG := neuralgas.Params{
		LearningRate_initial:     0.5,
		LearningRate_final:       0.005,
		InnerTemperature_initial: float64(prototypeCount) / 2.0,
		InnerTemperature_final:   0.01,
	}

	encParamsNG := neuralgas.EncParams{
		Ecd:          ecd,
		Enc:          enc,
		Eval:         eval,
		Params:       &params,
		Cmp:          cmp,
		Bootstrapper: bootstrapper,
		Dec:          dec,
	}

	ng, err := neuralgas.NewNorm(
		encSamples,
		uint(encSamples[0].Slots()),
		uint(prototypeCount),
		randomizer,
		paramsNG,
		encParamsNG,
		maxCores,
		logger)
	if err != nil {
		panic(err)
	}

	rankedPrototypes := make([]*util.RankedPrototype, prototypeCount)
	for i := range prototypeCount {
		rankedPrototypes[i] = &util.RankedPrototype{Prototype: ng.Prototypes()[i], Distance: nil}

		//-------------------------------------- TEST --------------------------------------------------------------------
		if ng.EncParams.Dec != nil {
			adaption, err := encrypt.DecSample(rankedPrototypes[i].Prototype, ecd, ng.EncParams.Dec)
			if err != nil {
				panic(err)
			}
			if logger != nil {
				logger.Info(fmt.Sprintf("Pre-Prototype: [%f, %f]", adaption.RawVector().Data[0], adaption.RawVector().Data[1]))
			}
		}
	}
	//------------------------------------ TEST END --------------------------------------------------------------------

	iteration := 0
	maxIteration := 30

	err = ng.TestStep(encSamples[0], rankedPrototypes, iteration, maxIteration, maxCores)
	if err != nil {
		panic(err)
	}

	// msgs, err := encrypt.DecSamples(ng.Prototypes(), ecd, dec, logger)
	// if err != nil {
	// 	panic(err)
	// }

	// // plotting.Plot2D(msgs, fmt.Sprintf("%d epoch(s)", i), fmt.Sprintf(".gitignore/plots/%dimg_0000%d", 0, i))
	// for i, msg := range msgs {
	// 	printing.PrintSlots(sampleSet[i].RawVector().Data, msg.RawVector().Data, 2)
	// 	println()

	// }
}

func toFloatArr(vecs []*mat.VecDense) (arr [][]float64) {
	arr = make([][]float64, len(vecs))

	for i := range vecs {
		arr[i] = vecs[i].RawVector().Data
	}

	return arr
}

// func fillDataset(dataset []*mat.VecDense) {
// 	for i := range dataset {
// 		rng := rand.Float64()
// 		dataset[i] = mat.NewVecDense(2, []float64{0.5*math.Sin(rng*2*math.Pi) + 0.5, 0.5*math.Cos(rng*2*math.Pi) + 0.5}) //circle
// 		// dataset[2*i] = mat.NewVecDense(2, []float64{rng, math.Cos(rng)})	// sin cos (1/2)
// 		// dataset[2*i+1] = mat.NewVecDense(2, []float64{rng, math.Sin(rng)}) // sin cos (2/2)
// 		// arr := make([]float64, dimensions)
// 		// arr[0] = 0.5*rng + 0.2
// 		// arr[1] = 0.2*rand.Float64() + 0.4
// 		// dataset[i] = mat.NewVecDense(dimensions, arr) // rectangle area
// 		// dataset[i] = mat.NewVecDense(2, []float64{0.5*rng + 0.2, 0.2*rand.Float64() + 0.4}) // rectangle area
// 	}

// }

func printRankedVecs(sampleCount int, ranked []*util.RankedPrototype, ecd *ckks.Encoder, dec *rlwe.Decryptor, logger *slog.Logger) {
	sorted := make([]*rlwe.Ciphertext, sampleCount)
	distances := make([]*rlwe.Ciphertext, sampleCount)
	for i := range sorted {
		sorted[i] = ranked[i].Prototype
		distances[i] = ranked[i].Distance
	}
	msgs, err := encrypt.DecSamplesThreaded(sorted, ecd, dec, 8, logger)
	if err != nil {
		panic(err)
	}
	distancesDec, err := encrypt.DecSamplesThreaded(distances, ecd, dec, 8, logger)
	if err != nil {
		panic(err)
	}
	for i, msg := range msgs {
		println(fmt.Sprintf("idx: %d, Inhalt: %f, distance: %f\n", i, msg.AtVec(0), distancesDec[i].AtVec(0)))
	}
}
