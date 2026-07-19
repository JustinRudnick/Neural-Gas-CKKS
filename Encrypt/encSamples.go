package encrypt

import (
	parallelize "NeuralGasCKKS/Parallelize"
	"fmt"
	"log/slog"
	"sync"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"gonum.org/v1/gonum/mat"
)

type ThreadBuffer struct {
	Ecd    *ckks.Encoder
	Enc    *rlwe.Encryptor
	Dec    *rlwe.Decryptor
	Cts    []*rlwe.Ciphertext
	Msgs   []*mat.VecDense
	Params *ckks.Parameters
	Logger *slog.Logger
}

func EcdSample(sample *mat.VecDense, pt *rlwe.Plaintext, ecd *ckks.Encoder) (err error) {
	return ecd.Encode(sample.RawVector().Data, pt)
}

func DcdSample(pt *rlwe.Plaintext, ecd *ckks.Encoder) (msg *mat.VecDense, err error) {
	arr := make([]float64, pt.Slots())
	if err := ecd.Decode(pt, arr); err != nil {
		return nil, err
	}
	return mat.NewVecDense(len(arr), arr), nil
}

/*
Returns a *[rlwe.Ciphertext] of the encrypted *[mat.VecDense] or nil and an error message on failure
*/
func EncSample(sample *mat.VecDense, ecd *ckks.Encoder, enc *rlwe.Encryptor, params *ckks.Parameters) (ct *rlwe.Ciphertext, err error) {

	prepSample := increaseDimsZero(sample, params)

	var pt *rlwe.Plaintext = ckks.NewPlaintext(*params, params.MaxLevel()) // Allocates a plaintext at the max level.
	if err = EcdSample(prepSample, pt, ecd); err != nil {
		return nil, err
	}

	if ct, err = enc.EncryptNew(pt); err != nil {
		return nil, err
	}

	return ct, nil
}

/*
Decrypts and Decodes a [rlwe.Ciphertext] and returns the message as [mat.VecDense] or [nil] on failure.
*/
func DecSample(ct *rlwe.Ciphertext, ecd *ckks.Encoder, dec *rlwe.Decryptor) (msg *mat.VecDense, err error) {
	pt := dec.DecryptNew(ct)
	result := make([]float64, pt.Slots())

	if err = ecd.Decode(pt, result); err != nil {
		return nil, err
	}

	return mat.NewVecDense(len(result), result), nil
}

func EncSamples(samples []*mat.VecDense, ecd *ckks.Encoder, enc *rlwe.Encryptor, params *ckks.Parameters, logger *slog.Logger) (cts []*rlwe.Ciphertext, err error) {
	return EncSamplesThreaded(samples, ecd, enc, params, 1, logger)
}

func DecSamples(cts []*rlwe.Ciphertext, ecd *ckks.Encoder, dec *rlwe.Decryptor, logger *slog.Logger) (msgs []*mat.VecDense, err error) {
	return DecSamplesThreaded(cts, ecd, dec, 1, logger)
}

/*
--- Values ---

samples ...slice of vectors to encrypt

maxCores ...the amount of Threads to use for the encryption

[optional] logger ...a logger for error messages

--- Description ---

Encrypts the passed <samples>.

Calls [runtime.SetDefaultGOMAXPROCS] in the end.

--- Returns ---

A slice of all *[rlwe.Ciphertext]s representing the encrypted samples or [nil] on failure.
*/
func EncSamplesThreaded(
	samples []*mat.VecDense,
	ecd *ckks.Encoder,
	enc *rlwe.Encryptor,
	params *ckks.Parameters,
	maxCores int,
	logger *slog.Logger,
) (cts []*rlwe.Ciphertext, err error) {
	cts = make([]*rlwe.Ciphertext, len(samples))

	parallelize.MultiThread(
		&ThreadBuffer{
			Ecd:    ecd,
			Enc:    enc,
			Cts:    cts,
			Logger: logger},
		samples,
		maxCores,
		func(tools *ThreadBuffer, subSamples []*mat.VecDense, sliceOff int, wg *sync.WaitGroup) {
			defer wg.Done()

			for innerOff := range subSamples {
				totalOffset := sliceOff + innerOff
				var ct *rlwe.Ciphertext
				ct, err = EncSample(subSamples[innerOff], ecd, enc, params)

				if err != nil && logger != nil {
					logger.Error(fmt.Sprintf("Encryption failed in goroutine at position: %d, msg: %s", totalOffset, err.Error()))
				}

				tools.Cts[totalOffset] = ct
			}
		})

	for i, ct := range cts {
		if ct == nil {
			err = fmt.Errorf("Process recognition: Encryption failed at index: %d", i)
			if logger != nil {
				logger.Error(err.Error())
			}
			return nil, err
		}
	}

	return cts, nil
}

/*
--- Values ---

cts ...slice of *[rlwe.Ciphertext] to decrypt

maxCores ...the amount of Threads to use for the encryption

[optional] logger ...a logger for error messages

--- Description ---

Decrypts the passed <cts>.

Calls [runtime.SetDefaultGOMAXPROCS] in the end.

--- Returns ---

A slice of all *[mat.VecDense]s representing the decrypted <cts> or [nil] on failure.
*/
func DecSamplesThreaded(cts []*rlwe.Ciphertext, ecd *ckks.Encoder, dec *rlwe.Decryptor, maxCores int, logger *slog.Logger) (msgs []*mat.VecDense, err error) {
	msgs = make([]*mat.VecDense, len(cts))

	parallelize.MultiThread(
		&ThreadBuffer{
			Ecd:    ecd,
			Dec:    dec,
			Msgs:   msgs,
			Logger: logger},
		cts,
		maxCores,
		func(tools *ThreadBuffer, subCts []*rlwe.Ciphertext, sliceOff int, wg *sync.WaitGroup) {
			defer wg.Done()

			for innerOff := range subCts {
				totalOffset := sliceOff + innerOff
				msg, err := DecSample(subCts[innerOff], ecd, dec)

				if err != nil && logger != nil {
					logger.Error(fmt.Sprintf("Decryption failed in goroutine at position: %d, msg: %s", totalOffset, err.Error()))
				}

				tools.Msgs[totalOffset] = msg
			}
		})

	for i, msg := range msgs {
		if msg == nil {
			err = fmt.Errorf("Process recognition: Decryption failed at index %d", i)
			if logger != nil {
				logger.Error(err.Error())
			}
			return nil, err
		}
	}

	return msgs, nil
}

//###################### Helper functions ##############################################################

// if the dimensions of vec does not match the required dimensions of params it will return a new [mat.VecDense] with the required dimensions.
// (Added dimensions are filled with 0)
func increaseDimsZero(vec *mat.VecDense, params *ckks.Parameters) (increasedDims *mat.VecDense) {
	dims, _ := vec.Dims()
	reqDims := 1 << params.LogN()
	if dims != reqDims {
		arr := make([]float64, reqDims)
		for i := range dims {
			arr[i] = vec.AtVec(i)
		}
		return mat.NewVecDense(reqDims, arr)
	}

	return vec
}
