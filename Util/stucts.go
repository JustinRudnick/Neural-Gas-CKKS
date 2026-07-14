package util

import "github.com/tuneinsight/lattigo/v6/core/rlwe"

type RankedPrototype struct {
	Prototype *rlwe.Ciphertext
	Distance  *rlwe.Ciphertext // a buffer for the distance at step function for the given sample
}
