package thresholdagent

import (
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/clover-network/threshold-crypto/utils"
	eth "github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

func GetScalar(sType SignatureType, message []byte, R, PublicKey *crypto.ECPoint) *big.Int {
	switch sType {
	case SignatureType_SCHNORRv1:
		return utils.GetScalar1(message, R, PublicKey)
	case SignatureType_SCHNORRv2:
		return utils.GetScalar2(message, R, PublicKey)
	}
	return big.NewInt(0)
}

func (sgn *SchnorrSignature) Verify() bool {
	curve := tss.EC()
	R := &crypto.ECPoint{}
	R.GobDecode(sgn.R)
	// s = r + k * x
	sigma := new(big.Int).SetBytes(sgn.S)

	dec, _ := eth.DecompressPubkey(sgn.PublicKey)
	pubKey, _ := crypto.NewECPoint(tss.EC(), dec.X, dec.Y)

	k := GetScalar(sgn.SType, sgn.SigningData, R, pubKey)
	negK := new(big.Int).Sub(curve.Params().N, k)

	//sG - kP ?= R
	sG := crypto.ScalarBaseMult(curve, sigma)
	kP := pubKey.ScalarMult(negK)
	RPrime, _ := sG.Add(kP)

	return RPrime.Equals(R)
	return true
}
