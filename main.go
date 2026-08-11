package main

import (
	encrypt "NeuralGasCKKS/Encrypt"
	neuralgas "NeuralGasCKKS/NeuralGas"
	plotting "NeuralGasCKKS/Plotting"
	test "NeuralGasCKKS/Test"
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
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"gonum.org/v1/gonum/mat"
)

func main() {

	var logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	var seed int64 = 22
	randomizer := rand.New(rand.NewSource(seed))
	trainCores := 1
	encCores := 1 //1 for deterministic purposes

	resPath := "C:/GitHub/Neural-Gas-CKKS/files/"
	resFile := "single.txt"

	imageNumber := 2

	epochs := 10
	scaleBits := 10 // ~3 decimal places precision

	//------------------
	// Initialization
	//------------------

	var err error
	var params ckks.Parameters

	scalingFactor := 45
	logAccuracy := 10
	level := 10
	logQ := util.FillSlice(scalingFactor, level+1)
	logQ[0] += logAccuracy

	//-------- for deterministic purposes
	key := []byte("key for research purposes") // 25 byte key. 0 - 32 bytes allowed
	prng, err := sampling.NewKeyedPRNG(key)
	if err != nil {
		panic(err)
	}

	//-------- end of deterministic purposes

	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:4, LogQP: 431.
	if params, err = ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN:            4,             // log2(ring degree) (4 is minimum)
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

	// kgen := rlwe.NewKeyGenerator(params) // Key Generator
	kgen := rlwe.NewTestKeyGeneratorWithKeyedPRNG(params, prng) // deterministic Key Generator
	sk := kgen.GenSecretKeyNew()                                // Secret Key
	ecd := ckks.NewEncoder(params)                              // Encoder
	// enc := rlwe.NewEncryptor(params, sk)     // Encryptor
	enc := rlwe.NewTestEncryptorWithKeyedPRNG(params, sk, prng) // deterministic Encryptor
	dec := rlwe.NewDecryptor(params, sk)                        // Decryptor
	rlk := kgen.GenRelinearizationKeyNew(sk)                    // Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)                     // Evaluation Key Set with the Relinearization Key
	eval := ckks.NewEvaluator(params, evk)                      // Evaluator

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

	test.Decryptor = dec

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

	fillDataset(dataset, randomizer) // deterministic tested

	plotting.Plot2D(dataset, fmt.Sprintf("circle of %d prototypes", sampleCount), fmt.Sprintf(".gitignore/plots/%dsample", imageNumber))

	//------------------
	// Encoding & Encryption
	//------------------

	var encSamples []*rlwe.Ciphertext
	if encSamples, err = encrypt.EncSamplesThreaded(dataset, ecd, enc, &params, encCores, logger); err != nil { //deterministic for maxCores == 1 -> not for maxCores != 1 tested
		panic(err)
	}

	//------------------
	// Neural Gas init
	//------------------

	// an identity cipher that needs to be initialized before training (needed in sorting for invStep)
	encrypt.IdentityCipherCreateInstance(encSamples[0].Slots(), ecd, enc, &params)

	n := len(cmp.MinimaxCompositeSignPolynomial)

	stepPoly := make([]bignum.Polynomial, n)

	for i := 0; i < n; i++ {
		stepPoly[i] = cmp.MinimaxCompositeSignPolynomial[i]
		// fmt.Fprintf(os.Stdin, "", nil, " ", stepPoly[i].Basis)

		for _, coeff := range stepPoly[i].Coeffs {
			co, _ := coeff.Real().Float64()
			fmt.Printf(" %f", co)
		}
		fmt.Println()
	}

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

	ng, err := neuralgas.NewNorm(
		encSamples,
		uint(encSamples[0].Slots()),
		uint(prototypeCount),
		randomizer,
		paramsNG,
		encParamsNG,
		encCores,
		logger)
	if err != nil {
		panic(err)
	}

	err = ng.TrainPlots(uint(epochs), scaleBits, uint(trainCores), fmt.Sprintf(".gitignore/plots/%dimg_", imageNumber), []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40})
	if err != nil {
		panic(err)
	}

	// open / create file and write down the contents
	file, err := os.OpenFile(fmt.Sprintf("%s%s", resPath, resFile), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	err = file.Truncate(0)
	if err != nil {
		panic(err)
	}

	arrMat, err := encrypt.DecSamplesThreaded(ng.Prototypes(), ecd, dec, trainCores, logger)
	if err != nil {
		panic(err)
	}

	for i := range arrMat {
		file.WriteString(fmt.Sprintf("%.17f, %.17f\n", arrMat[i].RawVector().Data[0], arrMat[i].RawVector().Data[1]))
	}

}

func fillDataset(dataset []*mat.VecDense, RNG *rand.Rand) {
	for i := range len(dataset) {
		rng := RNG.Float64()
		dataset[i] = mat.NewVecDense(2, []float64{0.5*math.Sin(rng*2*math.Pi) + 0.5, 0.5*math.Cos(rng*2*math.Pi) + 0.5}) //circle
		// dataset[2*i] = mat.NewVecDense(2, []float64{rng, math.Cos(rng)})	// sin cos (1/2)
		// dataset[2*i+1] = mat.NewVecDense(2, []float64{rng, math.Sin(rng)}) // sin cos (2/2)
		// dataset[i] = mat.NewVecDense(2, []float64{0.5*rng + 0.2, 0.2*rand.Float64() + 0.4}) // rectangle area
	}

}

func PrintSlice[T any](slice []T, printableElement func(elem T) any) {
	fmt.Printf("[")
	for i, elem := range slice {
		print(printableElement(elem))
		if i != len(slice)-1 {
			print(", ")
		}
	}
	fmt.Printf("]\n")
}
