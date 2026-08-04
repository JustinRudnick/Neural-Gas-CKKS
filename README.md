
Changes to Lattigo v6
   
   
**keygenerator.go** add new function:

// NewKeyGenerator creates a new KeyGenerator, from which the secret and public keys, as well as [EvaluationKey]. \newline
// \\
// CAUTION: uns only for testing purposes \\ 
func NewTestKeyGeneratorWithKeyedPRNG(params ParameterProvider, prng *sampling.KeyedPRNG) *KeyGenerator { \\ 
    return &KeyGenerator{ \\
        Encryptor: NewTestEncryptorWithKeyedPRNG(params, nil, prng), \\ 
        pool:      NewPool(params.GetRLWEParameters().RingQP()), \\
    } \\
} \\

**encryptor.go** change function name:

newTestEncryptorWithKeyedPRNG $\rightarrow$ NewTestEncryptorWithKeyedPRNG