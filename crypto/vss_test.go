package crypto

import (
	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestReconstruct2(t *testing.T) {
	num, threshold := 5, 3

	secret1 := common.GetRandomPositiveInt(tss.EC().Params().N)
	secret2 := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	vs1, shares1, err := vss.Create(threshold, secret1, ids)
	assert.NoError(t, err)

	vs2, shares2, err := vss.Create(threshold, secret2, ids)
	assert.NoError(t, err)

	vsf, _ := AddVs(vs1, vs2)
	shf, _ := AddShares(shares1, shares2)

	secretf := new(big.Int).Add(secret1, secret2)
	secretf = secretf.Mod(secretf, tss.EC().Params().N)

	sec, err := shf[:threshold+1].ReConstruct()
	assert.Nil(t, err)
	assert.Equal(t, sec, secretf)
	for _, next := range shf {
		assert.True(t, next.Verify(threshold, vsf))
	}

}
