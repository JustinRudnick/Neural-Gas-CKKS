package main

import (
	encrypt "NeuralGasCKKS/Encrypt"
	neuralgas "NeuralGasCKKS/NeuralGas"
	plotting "NeuralGasCKKS/Plotting"
	util "NeuralGasCKKS/Util"
	"fmt"
	"log/slog"
	"math"
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

	var logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	var seed int64 = 22
	randomizer := rand.New(rand.NewSource(seed))
	maxCores := 8

	//------------------
	// Initialization
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

	// var factor float64 = 1
	// var imagePath string = ".gitignore/imageSamples/walking_man.jpg"

	// sampleSetRed := input.ImageToSampleSetReverse(imagePath, func(x, y int, img *image.Image) bool {
	// 	r, _, _, a := (*img).At(x, y).RGBA()
	// 	return rand.Float64() > factor*float64(r)/float64(0xffff)*float64(a)/float64(0xffff)
	// })
	// sampleSetGreen := input.ImageToSampleSetReverse(imagePath, func(x, y int, img *image.Image) bool {
	// 	_, g, _, a := (*img).At(x, y).RGBA()
	// 	return rand.Float64() > factor*float64(g)/float64(0xffff)*float64(a)/float64(0xffff)
	// })
	// sampleSetBlue := input.ImageToSampleSetReverse(imagePath, func(x, y int, img *image.Image) bool {
	// 	_, _, b, a := (*img).At(x, y).RGBA()
	// 	return rand.Float64() > factor*float64(b)/float64(0xffff)*float64(a)/float64(0xffff)
	// })
	// sampleSetAvg := input.ImageToSampleSetReverse(imagePath, func(x, y int, img *image.Image) bool {
	// 	r, g, b, a := (*img).At(x, y).RGBA()
	// 	r = uint32(float64(r+g+b) / 3.0)
	// 	return rand.Float64() > factor*float64(b)/float64(0xffff)*float64(a)/float64(0xffff)
	// })

	// plotting.Plot2D(sampleSetRed, "red filter", ".gitignore/imagePlots/sample41")
	// println("sample generated")
	// plotting.Plot2D(sampleSetGreen, "green filter", ".gitignore/imagePlots/sample42")
	// println("sample generated")
	// plotting.Plot2D(sampleSetBlue, "blue filter", ".gitignore/imagePlots/sample43")
	// println("sample generated")
	// plotting.Plot2D(sampleSetAvg, "average filter", ".gitignore/imagePlots/sample44")
	// println("sample generated")

	sampleCount := 40
	var dataset []*mat.VecDense = make([]*mat.VecDense, sampleCount)

	fillDataset(dataset)

	plotting.Plot2D(dataset, fmt.Sprintf("circle of %d prototypes", sampleCount), ".gitignore/plots/sample")

	//------------------
	// Encoding & Encryption
	//------------------

	var encSamples []*rlwe.Ciphertext
	if encSamples, err = encrypt.EncSamplesThreaded(dataset, ecd, enc, &params, maxCores, logger); err != nil {
		panic(err)
	}

	//------------------
	// Neural Gas init
	//------------------

	prototypeCount := 10

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

	// for i := range 10 {
	// 	var err error
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

	err = ng.Train(10, uint(maxCores))
	if err != nil {
		panic(err)
	}

	msgs, err := encrypt.DecSamples(ng.Prototypes(), ecd, dec, logger)
	if err != nil {
		panic(err)
	}

	plotting.Plot2D(msgs, fmt.Sprintf("%d epoch(s)", 10), fmt.Sprintf(".gitignore/plots/%dimg_0000%d", 3, 10))
	// for _, msg := range msgs {
	// 	// printing.PrintSlots(msg.RawVector().Data, msg.RawVector().Data, 2)
	// 	println()
	// }

	// }
	// err = ng.TrainPlots(10, uint(maxCores), fmt.Sprintf(".gitignore/plots/%dimg_", 2), []int{0, 1, 2, 3, 4, 10, 20, 30, 40})
	// if err != nil {
	// 	panic(err)
	// }

}

// func main() {
// 	var seed int64 = 22

// 	randomizer := rand.New(rand.NewSource(seed))
// 	var dataset []*mat.VecDense = make([]*mat.VecDense, 100)

// 	for i := range len(dataset) {
// 		rng := rand.Float64()
// 		// dataset[i] = mat.NewVecDense(2, []float64{0.5*math.Sin(rng*2*math.Pi) + 0.5, 0.5*math.Cos(rng*2*math.Pi) + 0.5}) //circle
// 		// dataset[2*i] = mat.NewVecDense(2, []float64{rng, math.Cos(rng)})	// sin cos (1/2)
// 		// dataset[2*i+1] = mat.NewVecDense(2, []float64{rng, math.Sin(rng)}) // sin cos (2/2)
// 		dataset[i] = mat.NewVecDense(2, []float64{0.5*rng + 0.2, 0.2*rand.Float64() + 0.4}) // rectangle area
// 	}

// 	prototypeCount := 300

// 	params := neuralgas.Params{
// 		LearningRate_start:     0.5,
// 		LearningRate_end:       0.005,
// 		InnerTemperature_start: float64(prototypeCount) / 2.0,
// 		InnerTemperature_end:   0.01}

// 	ng500 := neuralgas.NewNorm(dataset, uint(prototypeCount), randomizer, params)
// 	ng2000 := neuralgas.NewNorm(dataset, uint(prototypeCount), randomizer, params)
// 	// ng10000 := neuralgas.NewNorm(dataset, uint(prototypeCount), randomizer, params)

// 	plotting.Plot2D(dataset, "Samples", "plots/samples")

// 	testreihe := 0
// 	for i := range 10 {
// 		ng := neuralgas.NewNorm(dataset,
// 			uint(prototypeCount),
// 			randomizer,
// 			params)
// 		ng.Train(uint(i))
// 		plotting.Plot2D(ng.GetPrototypes(), fmt.Sprintf("%d epoch(s)", i), fmt.Sprintf("plots/%dimg_0000%d", testreihe, i))
// 	}

// 	ng500.Train(500)
// 	plotting.Plot2D(ng500.GetPrototypes(), "500 epochs", fmt.Sprintf("plots/%dimg_00500", testreihe))
// 	ng2000.Train(2000)
// 	plotting.Plot2D(ng2000.GetPrototypes(), "2000 epochs", fmt.Sprintf("plots/%dimg_02000", testreihe))
// 	// ng10000.Train(10000)
// 	// plotting.Plot2D(ng10000.GetPrototypes(), "10000 epochs", fmt.Sprintf("plots/%dimg_10000", testreihe))

// }

// func randArr(dimensions int, randomizer rand.Rand) []float64 {
// 	arr := make([]float64, dimensions)
// 	for i := range dimensions {
// 		arr[i] = randomizer.Float64()
// 	}
// 	return arr
// }

func fillDataset(dataset []*mat.VecDense) {
	for i := range len(dataset) {
		rng := rand.Float64()
		dataset[i] = mat.NewVecDense(2, []float64{0.5*math.Sin(rng*2*math.Pi) + 0.5, 0.5*math.Cos(rng*2*math.Pi) + 0.5}) //circle
		// dataset[2*i] = mat.NewVecDense(2, []float64{rng, math.Cos(rng)})	// sin cos (1/2)
		// dataset[2*i+1] = mat.NewVecDense(2, []float64{rng, math.Sin(rng)}) // sin cos (2/2)
		// dataset[i] = mat.NewVecDense(2, []float64{0.5*rng + 0.2, 0.2*rand.Float64() + 0.4}) // rectangle area
	}

}
