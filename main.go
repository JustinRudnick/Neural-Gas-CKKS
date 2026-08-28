package main

import (
	encrypt "NeuralGasCKKS/Encrypt"
	input "NeuralGasCKKS/Input"
	neuralgas "NeuralGasCKKS/NeuralGas"
	plotting "NeuralGasCKKS/Plotting"
	test "NeuralGasCKKS/Test"
	util "NeuralGasCKKS/Util"
	"fmt"
	"image"
	"log/slog"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/comparison"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/minimax"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"gonum.org/v1/gonum/mat"
)

func main() {
	//-----------------
	//standard init
	//-----------------
	var isSeeded bool = false
	var isPlotted bool = false
	var isFiled bool = false
	var isCleanedUp bool = false
	var useRandomSampleSet bool = false

	var samplePath string = "./.gitignore/imageSamples/"
	var sampleFile string = "man.jpg"

	var err error

	var logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	var seed int64
	randomizer := rand.New(rand.NewSource(rand.Int63()))
	trainCores := 1
	encCores := 1 //1 for deterministic purposes

	resPath := "./" //"C:/GitHub/Neural-Gas-CKKS/files/"
	resFile := "default.txt"

	imageNumber := 0 //prefix for plots

	epochs := 10
	scaleBits := 10 // ~3 decimal places precision

	logScalingFactor := 45
	logAccuracy := 10 // accuracy bits additional
	level := 10

	sampleCount := 40
	prototypeCount := 10

	//-----------------
	//process input
	//-----------------

	for i, arg := range os.Args {
		switch arg[0] {
		case '-':
			switch strings.ToLower(arg[1:]) {
			case "help", "h", "?":
				printHelpInfo(resPath, level, logScalingFactor, logAccuracy)
				return
			case "plot":
				imageNumber, err = strconv.Atoi(os.Args[i+1])
				if err != nil {
					panic(err)
				}
				isPlotted = true
			case "cores", "c":
				trainCores, err = strconv.Atoi(os.Args[i+1])
				if err != nil {
					panic(err)
				}
			case "seed":
				seed, err = strconv.ParseInt(os.Args[i+1], 10, 64)
				if err != nil {
					panic(err)
				}
				randomizer = rand.New(rand.NewSource(seed))
				isSeeded = true
			case "prototypes", "p":
				prototypeCount, err = strconv.Atoi(os.Args[i+1])
				if err != nil {
					panic(err)
				}
			case "samples", "s":
				sampleCount, err = strconv.Atoi(os.Args[i+1])
				if err != nil {
					panic(err)
				}
				useRandomSampleSet = true
			case "epochs", "e":
				epochs, err = strconv.Atoi(os.Args[i+1])
				if err != nil {
					panic(err)
				}
			case "file", "f":
				resFile = os.Args[i+1]
				isFiled = true
			case "path":
				resPath = os.Args[i+1]
			case "levels", "l":
				level, err = strconv.Atoi(os.Args[i+1])
				if err != nil {
					panic(err)
				}
			case "logscale", "sc":
				logScalingFactor, err = strconv.Atoi(os.Args[i+1])
				if err != nil {
					panic(err)
				}
			case "logaccuracy", "ac":
				logAccuracy, err = strconv.Atoi(os.Args[i+1])
				if err != nil {
					panic(err)
				}
			case "clean":
				scaleBits, err = strconv.Atoi(os.Args[i+1])
				if err != nil {
					panic(err)
				}
				isCleanedUp = true
			default:
			}
		case '?':
			printHelpInfo(resPath, level, logScalingFactor, logAccuracy)
			return

		default:
		}
	}

	//-------------------------------------------------- true main ----------------------------------------------

	//------------------
	// Initialization
	//------------------

	var params ckks.Parameters

	logQ := util.FillSlice(logScalingFactor, level+1)
	logQ[0] += logAccuracy

	//-------- for deterministic purposes
	key := []byte("key for research purposes") // 25 byte key. 0 - 32 bytes allowed
	prng, err := sampling.NewKeyedPRNG(key)
	if err != nil {
		panic(err)
	}

	//-------- end of deterministic purposes

	// LogN:4, LogQP: sum of all LogQ and LogP components.
	if params, err = ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN:            4,                // log2(ring degree) (4 is minimum)
			LogQ:            logQ,             // log2(primes Q) (ciphertext modulus)
			LogP:            []int{61},        // log2(primes P) (auxiliary modulus)
			LogDefaultScale: logScalingFactor, // log2(scale)
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

	var kgen *rlwe.KeyGenerator
	var enc *rlwe.Encryptor
	if isSeeded {
		kgen = rlwe.NewTestKeyGeneratorWithKeyedPRNG(params, prng) // deterministic Key Generator
	} else {
		kgen = rlwe.NewKeyGenerator(params) // Key Generator
	}
	sk := kgen.GenSecretKeyNew()   // Secret Key
	ecd := ckks.NewEncoder(params) // Encoder
	if isSeeded {
		enc = rlwe.NewTestEncryptorWithKeyedPRNG(params, sk, prng) // deterministic Encryptor
	} else {
		enc = rlwe.NewEncryptor(params, sk) // Encryptor
	}
	dec := rlwe.NewDecryptor(params, sk)     // Decryptor
	rlk := kgen.GenRelinearizationKeyNew(sk) // Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)  // Evaluation Key Set with the Relinearization Key
	eval := ckks.NewEvaluator(params, evk)   // Evaluator

	slots := 1 << params.LogN()
	batches := 1
	terms := slots / batches //terms per batch
	eval = eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(batches, terms), sk)...))

	if logger != nil {
		logger.Info("Generating bootstrapping keys...")
	}
	btpk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		panic(err)
	}
	if logger != nil {
		logger.Info("Bootstrapping keys generated.")
	}

	var bootstrapper *bootstrapping.Evaluator
	if bootstrapper, err = bootstrapping.NewEvaluator(btpParams, btpk); err != nil {
		panic(err)
	}
	cmp := comparison.NewEvaluator(params, minimax.NewEvaluator(params, eval, bootstrapper))

	test.Decryptor = dec //TODO remove

	//------------------
	// Samples init
	//------------------

	var dataset []*mat.VecDense

	if useRandomSampleSet {
		dataset = make([]*mat.VecDense, sampleCount)
		fillDataset(dataset, randomizer)
	} else {
		dataset = input.ImageToSampleSetReverse(fmt.Sprintf("%s%s", samplePath, sampleFile), func(x, y int, img *image.Image) bool {
			r, _, _, a := (*img).At(x, y).RGBA()
			// r = (r + g + b) / 3
			value := float64(r) * float64(a) / float64(0xffff)
			return (x*y)%2 == 1 && value < 0x6000
		})
	}

	plotting.Plot2D(dataset, fmt.Sprintf("sample set of %d samples", sampleCount), fmt.Sprintf(".gitignore/plots/%dsample", imageNumber))

	//------------------
	// Encoding & Encryption
	//------------------

	var encSamples []*rlwe.Ciphertext
	if encSamples, err = encrypt.EncSamplesThreaded(dataset, ecd, enc, &params, encCores, logger); err != nil { //deterministic for maxCores == 1 -> not for maxCores != 1
		panic(err)
	}

	//------------------
	// Neural Gas init
	//------------------

	// an identity cipher that needs to be initialized before training (needed in sorting for invStep)
	encrypt.IdentityCipherCreateInstance(encSamples[0].Slots(), ecd, enc, &params)

	paramsNG := neuralgas.Params{
		LearningRate_initial:     0.5,
		LearningRate_final:       0.005,
		InnerTemperature_initial: float64(prototypeCount) / 2.0,
		InnerTemperature_final:   0.01,
	}

	encParamsNG := neuralgas.EncParams{
		Ecd:             ecd,
		Enc:             enc,
		Eval:            eval,
		Params:          &params,
		Cmp:             cmp,
		Bootstrapper:    bootstrapper,
		Dec:             dec,
		LogCleanUpScale: 10,

		IsCleanedUp:   isCleanedUp,
		CleanBitScale: scaleBits,
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

	if isPlotted {
		plotEpochs := make([]int, 20)
		for i := range 10 {
			plotEpochs[2*i] = epochs / (i + 1)
			plotEpochs[2*i+1] = int(math.Round(float64(i+1) / float64(10) * float64(epochs)))
		}
		err = ng.TrainPlots(uint(epochs), uint(trainCores), fmt.Sprintf(".gitignore/plots/%dimg_", imageNumber), append(plotEpochs, 0))
		if err != nil {
			panic(err)
		}
	} else {
		err = ng.Train(uint(epochs), uint(trainCores))
		if err != nil {
			panic(err)
		}
	}

	if !isFiled {
		return
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

	var s string
	for i := range arrMat {
		s = ""
		sampleDims := 0

		if len(dataset) > 0 {
			sampleDims = len(dataset[0].RawVector().Data)
		}

		for dim := range sampleDims {
			s += fmt.Sprintf("%.17f", arrMat[i].RawVector().Data[dim])
			if dim < sampleDims-1 {
				s += ", "
			} else {
				s += "\n"
			}
		}
		file.WriteString(s)
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

func printHelpInfo(path string, maxLevel, logScalingFactor, logAccuracy int) {
	println("commands:")
	println("--- learning ---")
	println("-cores -c <int>\t\t...number of threads created. Default: 1")
	println("-seed <int64>\t\t...seed for randomizer. Default: random")
	println("-samples -s <int>\t...generates random sample set of passed amount of samples. Default: use image")
	println("-prototypes -p <int>\t...amount of prototypes created. Default: 500")
	println("-epochs -e <int>\t...amount of epochs used for training.")
	println("\n--- encryption ---")
	println("-logscale -sc <int>\t...log of scaling factor for encryption. Default: ", logScalingFactor)
	println("-levels -l <int>\t...max level of ciphertext. Default: ", maxLevel)
	println("-logaccuracy -ac <int>\t...additional accuracy to the scaling factor. Default: ", logAccuracy)
	println("-clean <int>\t\t...bits of precision safed before cleaning the ciphertext. Default: no cleaning")
	println("\n--- logging ---")
	println("-plot <int>\t\t...plots the results with given prefix. Default: no plotting")
	println("-file -f <string>\t...file to store decrypted prototype results. Default: no logging of results")
	println("-path <string>\t\t...path to store the file created with -file in. Default: ", path)
	println("-help -h -? ?\t\t...prints this.")
}
