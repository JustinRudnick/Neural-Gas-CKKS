package neuralgas

import (
	util "NeuralGasCKKS/Util"
	"fmt"
	"os"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func (ng *NeuralGas) TestStep(sample *rlwe.Ciphertext, rankedPrototypes []*util.RankedPrototype, iteration int, maxIterations int, maxCores int) {
	ng.step(sample, rankedPrototypes, iteration, maxIterations, maxCores)
	for _, prototype := range rankedPrototypes {
		fmt.Fprintln(os.Stdout, *prototype.Prototype)
		fmt.Printf("dist: %f\n", prototype.Distance)
	}
}
