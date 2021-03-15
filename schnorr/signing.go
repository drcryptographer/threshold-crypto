package schnorr

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/clover-network/threshold-crypto/thresholdagent"
	"github.com/clover-network/threshold-crypto/utils"
	"math/big"
)

func Verify(sgn *thresholdagent.SchnorrSignature, message []byte, pubKey *crypto.ECPoint) bool {
	curve := tss.EC()
	R := &crypto.ECPoint{}
	R.GobDecode(sgn.R)
	// s = r + k * x
	sigma := new(big.Int).SetBytes(sgn.S)
	k := getScalar(message, R, pubKey)
	negK := new(big.Int).Sub(curve.Params().N, k)

	//sG - kP ?= R
	sG := crypto.ScalarBaseMult(curve, sigma)
	kP := pubKey.ScalarMult(negK)
	RPrime, _ := sG.Add(kP)

	return RPrime.Equals(R)
}

type SigningCeremony struct {
	*CloverShare
	dkg     *KeyGen
	message []byte
	sigma_i *big.Int
}

func NewSigningCeremony(agentKey *ecdsa.PrivateKey, agentCerts map[int32]*x509.Certificate, SessionId string, id int32, message []byte) *SigningCeremony {
	sc := &CloverShare{}
	sc.ReadFromFile(id)
	dkg := NewKeyGen(agentKey, agentCerts, SessionId, id, sc.Threshold)
	return &SigningCeremony{
		CloverShare: sc,
		dkg:         &dkg,
		message:     message,
	}
}

func (sc *SigningCeremony) PublicKey() *crypto.ECPoint {
	return sc.CloverShare.Vs[0]
}

func (sc *SigningCeremony) R() *crypto.ECPoint {
	return sc.dkg.GetPublicKey()
}

func (sc *SigningCeremony) Round1() (*thresholdagent.SchnorrRound1Msg, error) {
	var ids []int32
	for _, next := range sc.dkg.agentCerts {
		ids = append(ids, utils.GetId(next))
	}
	return sc.dkg.Round1(ids)
}

func (sc *SigningCeremony) Round2(round1 ...*thresholdagent.SchnorrRound1Msg) ([]*thresholdagent.SchnorrRound2Msg, error) {
	return sc.dkg.Round2(round1...)
}

func (sc *SigningCeremony) Round3(round2 ...*thresholdagent.SchnorrRound2Msg) (*thresholdagent.SchnorrRound3Msg, error) {
	_, err := sc.dkg.Round3(round2...)
	if err != nil {
		return nil, err
	}
	r_i := sc.dkg.Share.Share
	k := getScalar(sc.message, sc.R(), sc.PublicKey())

	sigma_i := new(big.Int).Mul(k, sc.Share.Share)
	sigma_i = new(big.Int).Add(sigma_i, r_i)
	sigma_i = new(big.Int).Mod(sigma_i, tss.EC().Params().N)

	sc.sigma_i = sigma_i
	return &thresholdagent.SchnorrRound3Msg{
		SessionId: sc.dkg.SessionId,
		SenderId:  sc.dkg.Id(),
		Data: &thresholdagent.SchnorrRound3Msg_SigmaI{
			SigmaI: sigma_i.Bytes(),
		},
	}, nil
}

func getScalar(message []byte, R, PublicKey *crypto.ECPoint) *big.Int {
	sha := sha256.New()
	sha.Write(message)
	buffer, _ := R.GobEncode()
	sha.Write(buffer)

	buffer, _ = PublicKey.GobEncode()
	sha.Write(buffer)

	result := big.NewInt(0).SetBytes(sha.Sum(nil))

	return result
}

func (sc *SigningCeremony) Round4(round3 ...*thresholdagent.SchnorrRound3Msg) (*thresholdagent.SchnorrSignature, error) {
	//reconstruct sigma
	sharesFinal := make(vss.Shares, len(round3)+1)
	for i, next := range round3 {
		data := next.Data.(*thresholdagent.SchnorrRound3Msg_SigmaI)
		sharesFinal[i] = &vss.Share{
			Threshold: sc.Share.Threshold,
			ID:        big.NewInt(int64(next.SenderId)),
			Share:     new(big.Int).SetBytes(data.SigmaI), //SigmaI
		}
	}
	sharesFinal[len(round3)] = &vss.Share{
		Threshold: sc.Share.Threshold,
		ID:        sc.ID,
		Share:     sc.sigma_i,
	}

	s, err := sharesFinal.ReConstruct()
	if err != nil {
		return nil, err
	}
	buffer, _ := sc.dkg.GetPublicKey().GobEncode()
	sgn := &thresholdagent.SchnorrSignature{
		SenderId: sc.dkg.Id(),
		R:        buffer,
		S:        s.Bytes(),
	}
	if !Verify(sgn, sc.message, sc.PublicKey()) {
		return nil, fmt.Errorf("the computed signature is not valid")
	}
	//verify signature
	return sgn, nil
}
