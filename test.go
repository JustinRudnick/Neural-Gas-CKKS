// package main

// import (
// 	encrypt "NeuralGasCKKS/Encrypt"
// 	"fmt"
// 	"log/slog"
// 	"math"
// 	"math/rand"
// 	"os"

// 	"github.com/JustinRudnick/CKKS-Lattigo-Examples/printing"
// 	"github.com/tuneinsight/lattigo/v6/core/rlwe"
// 	"github.com/tuneinsight/lattigo/v6/ring"
// 	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
// 	"gonum.org/v1/gonum/mat"
// )

// func main() {

// 	var logger *slog.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
// 	maxCores := 8

// 	//------------------
// 	// Initialization
// 	//------------------

// 	var err error
// 	var params ckks.Parameters

// 	if params, err = ckks.NewParametersFromLiteral(
// 		ckks.ParametersLiteral{
// 			LogN:            4,                                     // log2(ring degree)
// 			LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
// 			LogP:            []int{61},                             // log2(primes P) (auxiliary modulus)
// 			LogDefaultScale: 45,                                    // log2(scale)
// 			RingType:        ring.ConjugateInvariant,
// 		}); err != nil {
// 		panic(err)
// 	}

// 	kgen := rlwe.NewKeyGenerator(params) // Key Generator
// 	sk := kgen.GenSecretKeyNew()         // Secret Key
// 	ecd := ckks.NewEncoder(params)       // Encoder
// 	enc := rlwe.NewEncryptor(params, sk) // Encryptor
// 	dec := rlwe.NewDecryptor(params, sk) // Decryptor

// 	//------------------
// 	// Samples init
// 	//------------------

// 	sampleSet := make([]*mat.VecDense, 1<<params.LogN())
// 	fillDataset(sampleSet)

// 	//------------------
// 	// Encoding & Encryption
// 	//------------------

// 	var encSamples []*rlwe.Ciphertext
// 	if encSamples, err = encrypt.EncSamplesThreaded(sampleSet, ecd, enc, &params, maxCores, logger); err != nil {
// 		panic(err)
// 	}

// 	var decSamples []*mat.VecDense
// 	if decSamples, err = encrypt.DecSamplesThreaded(encSamples, ecd, dec, maxCores, logger); err != nil {
// 		for i, vec := range decSamples {
// 			fmt.Fprintf(os.Stdout, "Idx: %d, Value: %T\n", i, *vec)
// 		}
// 		panic(err)
// 	}

// 	want := toFloatArr(sampleSet)
// 	have := toFloatArr(decSamples)

// 	for i := range 10 {
// 		printing.PrintSlots(want[i], have[i], 2)
// 	}

// }

// func toFloatArr(vecs []*mat.VecDense) (arr [][]float64) {
// 	arr = make([][]float64, len(vecs))

// 	for i := range vecs {
// 		arr[i] = vecs[i].RawVector().Data
// 	}

// 	return arr
// }

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
