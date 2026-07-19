package globals

import (
	"log/slog"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

var DECRYPTOR *rlwe.Decryptor
var LOGGER *slog.Logger
var ECD *ckks.Encoder
