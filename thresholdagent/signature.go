package thresholdagent

import (
	"bytes"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/clover-network/threshold-crypto/utils"
	eth "github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

func GetScalar(sType SignatureType, message [32]byte, r []byte, PublicKey *crypto.ECPoint) *big.Int {
	switch sType {
	case SignatureType_SCHNORRv1:
		return utils.GetBip340E(PublicKey.X(), PublicKey.Y(), r, message)
	case SignatureType_SCHNORRv2:
		return utils.GetScalar2(message, r, PublicKey)
	}
	return big.NewInt(0)
}

func (sgn *SchnorrSignature) Verify() bool {
	curve := tss.EC()
	// s = r + k * x
	sigma := new(big.Int).SetBytes(sgn.S)

	dec, _ := eth.DecompressPubkey(sgn.PublicKey)
	pubKey, _ := crypto.NewECPoint(tss.EC(), dec.X, dec.Y)

	var msg [32]byte
	copy(msg[:], sgn.SigningData)

	k := GetScalar(sgn.SType, msg, sgn.R, pubKey)
	negK := new(big.Int).Sub(curve.Params().N, k)

	//sG - kP ?= R
	sG := crypto.ScalarBaseMult(curve, sigma)
	kP := pubKey.ScalarMult(negK)
	RPrime, _ := sG.Add(kP)

	return bytes.Compare(sgn.R, RPrime.X().Bytes()) == 0
	return true
}
