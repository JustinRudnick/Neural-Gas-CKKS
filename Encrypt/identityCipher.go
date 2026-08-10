package encrypt

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

var instances = make(map[int]*rlwe.Ciphertext)

/*
Returns a [rlwe.Ciphertext] that represents an encrypted identity vector of <slots> dimensions.
*/
func IdentityCipher(slots int, ecd *ckks.Encoder, enc *rlwe.Encryptor, params *ckks.Parameters) (identity *rlwe.Ciphertext, err error) {
	oneSlice := make([]float64, slots)
	for i := range oneSlice {
		oneSlice[i] = 1
	}
	var pt *rlwe.Plaintext = ckks.NewPlaintext(*params, params.MaxLevel())
	err = ecd.Encode(oneSlice, pt)
	if err != nil {
		return nil, err
	}
	identity, err = enc.EncryptNew(pt)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

func IdentityCipherCreateInstance(slots int, ecd *ckks.Encoder, enc *rlwe.Encryptor, params *ckks.Parameters) (err error) {
	instances[slots], err = IdentityCipher(slots, ecd, enc, params)
	return err
}

func IdentityCipherInstance(slots int) (identity *rlwe.Ciphertext, err error) {
	if instances[slots] != nil {
		return instances[slots].CopyNew(), nil
	}
	return nil, fmt.Errorf("identity ciphertext does not exist, please use IdentityCipherCreateInstance() to create it.")
}
