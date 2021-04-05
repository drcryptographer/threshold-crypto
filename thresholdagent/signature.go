package thresholdagent

import (
	"bytes"
	_ "crypto/elliptic"
	"encoding/json"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/clover-network/threshold-crypto/utils"
	eth "github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

func (x *EcdsaRoundMessage) GetParsedMessages() []tss.Message {
	messages, _ := UnMarshalMessageArray(x.Messages)
	return messages
}

func (x *EcdsaRoundMessage) SetMessages(msgs []tss.Message) {
	x.Messages, _ = MarshalMessageArray(msgs)
}

func (sgn *SchnorrSignature) Bip340Signature() [64]byte {
	var result [64]byte
	copy(result[:32], sgn.R)
	copy(result[32:], sgn.S)
	return result
}

//publicKey is compressed
func (sgn *SchnorrSignature) FromBip340Signature(publicKey [33]byte, message [32]byte, signature [64]byte) {
	sgn.SType = SignatureType_SCHNORRv1
	sgn.R = signature[:32]
	sgn.S = signature[32:]
	sgn.SigningData = message[:]
	sgn.CompressedPublicKey = publicKey[:]
}

//publicKey is compressed
func (sgn *SchnorrSignature) FromEthSignature(publicKey [33]byte, message, R, S [32]byte) {
	sgn.SType = SignatureType_SCHNORRv2
	sgn.R = R[:]
	sgn.S = S[:]
	sgn.SigningData = message[:]
	sgn.CompressedPublicKey = publicKey[:]
}

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
	if sgn.SType != SignatureType_SCHNORRv2 {
		return false
	}
	curve := tss.EC()
	// s = k - xe mod N where Rx, Ry = eG
	sigma := new(big.Int).SetBytes(sgn.S)
	dec, _ := eth.DecompressPubkey(sgn.CompressedPublicKey)
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
	if sgn.SType != SignatureType_SCHNORRv1 {
		return false
	}
	curve := tss.EC()
	// s = r + k * x
	sigma := new(big.Int).SetBytes(sgn.S)
	x, y, _ := utils.LiftX(curve, new(big.Int).SetBytes(sgn.CompressedPublicKey[1:]))

	var msg [32]byte
	copy(msg[:], sgn.SigningData)

	e := utils.GetBip340E(x, y, sgn.R, msg)
	negE := new(big.Int).Sub(curve.Params().N, e)

	P, _ := crypto.NewECPoint(curve, x, y)
	//sG - eP ?= R
	sG := crypto.ScalarBaseMult(curve, sigma)
	eP := P.ScalarMult(negE)
	RPrime, _ := sG.Add(eP)

	if !utils.IsEven(RPrime.Y()) {
		return false
	}
	if !RPrime.IsOnCurve() {
		return false
	}
	return bytes.Equal(sgn.R, utils.IntToBytes(RPrime.X()))
}

func MarshalMessage(msg tss.Message) ([]byte, error) {
	buffer, _, _ := msg.WireBytes()
	message := struct {
		Index       int
		IsBroadcast bool

		Id      string
		Moniker string
		Wire    []byte
		Key     []byte
	}{
		Index:       msg.GetFrom().Index,
		Id:          msg.GetFrom().Id,
		Moniker:     msg.GetFrom().Moniker,
		IsBroadcast: msg.IsBroadcast(),
		Wire:        buffer,
		Key:         msg.GetFrom().Key,
	}
	return json.Marshal(&message)
}
func UnMarshalMessage(msg []byte) (tss.Message, error) {
	message := struct {
		Index       int
		IsBroadcast bool
		Wire        []byte
		Id          string
		Moniker     string
		Key         []byte
	}{}
	json.Unmarshal(msg, &message)
	from := tss.NewPartyID(message.Id, message.Moniker, new(big.Int).SetBytes(message.Key))
	from.Index = message.Index
	return tss.ParseWireMessage(message.Wire, from, message.IsBroadcast)
}
func UnMarshalMessageArray(msg [][]byte) ([]tss.Message, error) {
	var result = make([]tss.Message, len(msg))
	var err error
	for i := 0; i < len(result); i++ {
		if result[i], err = UnMarshalMessage(msg[i]); err != nil {
			return nil, err
		}
	}
	return result, nil
}
func MarshalMessageArray(msg []tss.Message) ([][]byte, error) {
	var result = make([][]byte, len(msg))
	var err error
	for i := 0; i < len(result); i++ {
		if result[i], err = MarshalMessage(msg[i]); err != nil {
			return nil, err
		}
	}
	return result, nil
}
