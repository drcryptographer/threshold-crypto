package thresholdagent

import (
	"bytes"
	_ "crypto/elliptic"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/clover-network/threshold-crypto/utils"
	eth "github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

func (sgn *SchnorrSignature) Verify() bool {
	switch sgn.SType {
	case SignatureType_SCHNORRv1:
		return sgn.VerifyBip340()
	case SignatureType_SCHNORRv2:
		return sgn.VerifyEth()
	}
	return false
}
func (sgn *SchnorrSignature) VerifyEth() bool {
	curve := tss.EC()
	// s = k - xe mod N where Rx, Ry = eG
	sigma := new(big.Int).SetBytes(sgn.S)
	dec, _ := eth.DecompressPubkey(sgn.PublicKey)
	P, _ := crypto.NewECPoint(curve, dec.X, dec.Y)
	e := new(big.Int).SetBytes(sgn.R)

	//R := sG + eP = sG + exG
	sG := crypto.ScalarBaseMult(curve, sigma)
	kP := P.ScalarMult(e)
	R, _ := sG.Add(kP)

	e2 := utils.GetScalarETH(sgn.SigningData, R.X(), R.Y(), dec.X, dec.Y)
	return e.Cmp(e2) == 0

}

func (sgn *SchnorrSignature) VerifyBip340() bool {
	curve := tss.EC()
	// s = r + k * x
	sigma := new(big.Int).SetBytes(sgn.S)
	x, y, _ := utils.LiftX(curve, new(big.Int).SetBytes(sgn.PublicKey[1:]))

	var msg [32]byte
	copy(msg[:], sgn.SigningData)

	k := utils.GetBip340E(x, y, sgn.R, msg)
	negK := new(big.Int).Sub(curve.Params().N, k)

	P, _ := crypto.NewECPoint(curve, x, y)
	//sG - kP ?= R
	sG := crypto.ScalarBaseMult(curve, sigma)
	kP := P.ScalarMult(negK)
	RPrime, _ := sG.Add(kP)

	if !utils.IsEven(RPrime.Y()) {
		return false
	}
	if !RPrime.IsOnCurve() {
		return false
	}
	return bytes.Equal(sgn.R, utils.IntToByte(RPrime.X()))
}
