package main

import (
	noise "NeuralGasCKKS/Noise"
	util "NeuralGasCKKS/Util"
	"fmt"
	"strconv"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/comparison"
)

func main() {
	var compPoly [][]string = comparison.DefaultCompositePolynomialForSign
	var err error

	var messageSlotBound float64 = 1
	var messageSlots int = 16
	var maxLevel int = 10

	println("used message bound per slot: ", messageSlotBound)
	println("message slots: ", messageSlots)
	println("ciphertext maxLevel: ")

	polys := make([][]float64, len(compPoly))
	for i := range compPoly {
		polys[i], err = parsePoly(compPoly[i])
		if err != nil {
			fmt.Printf("ERR: %s\n", err.Error())
		}
	}

	AbsSums := make([]float64, len(compPoly))
	for i, poly := range polys {
		absValues := util.Abs(poly)
		AbsSums[i] = util.SumElems(absValues)

		// util.PrintSlice[float64, float64](poly, func(elem float64) float64 { return elem })
		// println()
	}

	print("sum of absolute values for all polynomials: ")
	util.PrintSlice(AbsSums, func(in float64, idx int) float64 { return in })
	println()

	print("product of sums (to this index): ")
	util.PrintSlice(AbsSums, func(in float64, idx int) float64 {
		return util.ProdElems(AbsSums[:idx+1])
	})
	println()

	print("polynomial degrees: ")
	util.PrintSlice(AbsSums, func(_ float64, idx int) int { return len(polys[idx]) - 1 })
	println()

	// ||m||^{can}_\infty
	canInfNormBound, err := noise.CanInfNormUpperBound(util.FillSlice(messageSlotBound, messageSlots))
	if err != nil {
		panic(err)
	}

	fmt.Printf("canonical message bound ||m||^{can}_\\infty: %f\n", canInfNormBound)

	//
	var Mf_composite float64
	Mf_composite = canInfNormBound

	var errorSlotBound float64 = 0.000001 //TODO use step error slot bound
	var beta0 float64 = errorSlotBound / canInfNormBound
	var betaD float64 = beta0
	var betaAsterisk float64 = noise.BetaAsteriskUpperBound(maxLevel)
	// println("beta0 of loop: ", 0, " is ", beta0)
	for i := range polys {
		betaD = noise.BetaDUpperBound(len(polys[i]), betaD, betaAsterisk)
		// println("betaD of loop: ", i+1, " is ", betaD)
	}

	// fmt.Printf("Step composite betaD bound: %f\n", betaD)
	fmt.Printf("recursive: Step composite error bound: %f\n", Mf_composite*betaD)

	println("-------------------------------------------")

	var newMessageBound float64 = canInfNormBound
	var newErrorBound float64 = errorSlotBound
	for i := range polys {
		newMessageBound, newErrorBound, err = noise.EvalPolyUpperBound(newMessageBound, newErrorBound, maxLevel, polys[i])
		if err != nil {
			panic(err)
		}
		// fmt.Printf("In loop %d msgB: %.15f, errB: %.15f\n", i+1, newMessageBound, newErrorBound)
	}

	// newMsgBound, newErrBound, err := noise.UpperBoundEvalPoly(1, 0.005, 7, poly)
	// if err != nil {
	// 	fmt.Printf("ERR: %s\n", err.Error())
	// }

	// println("newMsgBound: ", newMsgBound)
	// println("newErrBound: ", newErrBound)

	nuFactor := util.Prod(make([]float64, len(polys)), func(in float64, idx int) float64 {
		return util.SumElems(util.Abs(polys[idx]))
	})

	beta0Factor := util.Prod(make([]float64, len(polys)), func(in float64, idx int) float64 {
		return float64(len(polys[idx]))
	})

	betaAsteriskFactor := util.SumAny(polys, func(poly []float64, idx int) int {
		if idx < 1 {
			return 0
		}
		prodDegs := util.ProdAny(polys[idx:], func(poly []float64, idx int) int {
			return len(poly)
		})
		prodDegs *= len(polys[idx-1]) - 1

		return prodDegs + len(polys[len(polys)-1]) - 1
	})

	println("nu factor: ", nuFactor)
	println("beta0 factor: ", beta0Factor)
	println("betaAsterisk factor: ", betaAsteriskFactor)

	println()

	println("composite Mf: ", canInfNormBound*nuFactor)
	println("composite err bound: ", (beta0*beta0Factor+betaAsterisk*float64(betaAsteriskFactor))*canInfNormBound*nuFactor)

}

func parsePoly(coeffStr []string) (coeffs []float64, err error) {
	coeffs = make([]float64, len(coeffStr))
	for i := range coeffStr {
		coeffs[i], err = strconv.ParseFloat(coeffStr[i], 64)
		if err != nil {
			return nil, fmt.Errorf("could not parse polynomial from string slice: %s", err.Error())
		}
	}
	return coeffs, nil
}
