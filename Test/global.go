package test

import (
	"log/slog"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

var Logger *slog.Logger
var Bootstrapper *bootstrapping.Evaluator
var Decryptor *rlwe.Decryptor
var Ecd *ckks.Encoder
