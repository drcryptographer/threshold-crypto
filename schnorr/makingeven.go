package schnorr

import (
	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
	"math/big"
)

//&Share{Threshold: threshold, ID: indexes[i], Share: share}

func sampleDeterministicPolynomial(threshold int, secret *big.Int) []*big.Int {
	q := tss.EC().Params().N
	v := make([]*big.Int, threshold+1)
	v[0] = secret
	for i := 1; i <= threshold; i++ {
		ai := new(big.Int).Exp(big.NewInt(65337), big.NewInt(int64(i)), q)
		v[i] = ai
	}
	return v
}
func evaluatePolynomial(threshold int, v []*big.Int, id *big.Int) (result *big.Int) {
	q := tss.EC().Params().N
	modQ := common.ModInt(q)
	result = new(big.Int).Set(v[0])
	X := big.NewInt(int64(1))
	for i := 1; i <= threshold; i++ {
		ai := v[i]
		X = modQ.Mul(X, id)
		aiXi := new(big.Int).Mul(ai, X)
		result = modQ.Add(result, aiXi)
	}
	return
}
