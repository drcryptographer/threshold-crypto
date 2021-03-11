package crypto

import (
	"errors"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"math/big"
)

func AddVs(vs vss.Vs, next vss.Vs) (vss.Vs, error) {
	if len(vs) != len(next) {
		return nil, errors.New("they donot have equal size of points")
	}
	vsum := make(vss.Vs, len(vs))
	for i, n := range vs {
		vsum[i], _ = n.Add(next[i])
	}
	return vsum, nil
}
func AddShares(shares vss.Shares, next vss.Shares) (vss.Shares, error) {
	if len(shares) != len(next) {
		return nil, errors.New("they donot have equal size of shares")
	}
	sum := make(vss.Shares, len(next))
	var err error
	for i, n := range next {
		sum[i], err = AddShare(n, shares[i])
		if err != nil {
			return nil, err
		}
	}
	return sum, nil
}

func AddShare(share *vss.Share, next *vss.Share) (*vss.Share, error) {
	if share.ID != next.ID {
		return nil, errors.New("they do not have common id")
	}
	if share.Threshold != next.Threshold {
		return nil, errors.New("they do not have common threshold")
	}
	sum := &vss.Share{
		Threshold: share.Threshold,
		ID:        share.ID,
		Share:     new(big.Int).Add(share.Share, next.Share),
	}
	sum.Share = sum.Share.Mod(sum.Share, tss.EC().Params().N)
	return sum, nil
}
