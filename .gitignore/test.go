package main

import (
	"time"
)

func main() {

	// var seed int64 = 1
	// var randomizer rand.Rand = *rand.New(rand.NewSource(seed))

	// prototypeCount := 300

	// var dataset []*mat.VecDense = make([]*mat.VecDense, 100)
	// for i := range len(dataset) {
	// 	rng := randomizer.Float64()
	// 	// dataset[i] = mat.NewVecDense(2, []float64{0.5*math.Sin(rng*2*math.Pi) + 0.5, 0.5*math.Cos(rng*2*math.Pi) + 0.5}) //circle
	// 	// dataset[2*i] = mat.NewVecDense(2, []float64{rng, math.Cos(rng)})	// sin cos (1/2)
	// 	// dataset[2*i+1] = mat.NewVecDense(2, []float64{rng, math.Sin(rng)}) // sin cos (2/2)
	// 	dataset[i] = mat.NewVecDense(2, []float64{0.5*rng + 0.2, 0.2*randomizer.Float64() + 0.4}) // rectangle area
	// }

	// params := neuralgas.Params{
	// 	LearningRate_start:     0.5,
	// 	LearningRate_end:       0.005,
	// 	InnerTemperature_start: float64(prototypeCount) / 2.0,
	// 	InnerTemperature_end:   0.01}

	// ng := neuralgas.NewNorm(dataset, uint(prototypeCount), &randomizer, params)

	// rankedPrototypes := make([]*neuralgas.RankedPrototype, prototypeCount)
	// for i := range rankedPrototypes {
	// 	rankedPrototypes[i] = neuralgas.NewRankedPrototype(ng.Prototypes()[i], 0)
	// }

	// iteration := 0
	// maxIterations := 1000
	// maxCores := 4
	// ng.TestStep(dataset[0], rankedPrototypes, iteration, maxIterations, maxCores)

	inital := time.Now()
	time.Sleep(3 * time.Second)
	println("vergangen: ", float64(time.Since(inital))/float64(time.Second))

}
