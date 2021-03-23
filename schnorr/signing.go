package schnorr

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/clover-network/threshold-crypto/thresholdagent"
	"math/big"
)

type SchnorrSigningCeremony struct {
	*CloverSchnorrShare
	Dkg     *SchnorrKeyGen
	sigma_i *big.Int
	Round0  *thresholdagent.SchnorrRound0Msg
}

func NewSchnorrSigningCeremony(sessionId string, caCert *x509.Certificate, agentKey *ecdsa.PrivateKey, agentCerts map[int32]*x509.Certificate, share *CloverSchnorrShare) *SchnorrSigningCeremony {
	dkg := NewSchnorrKeyGen(sessionId, caCert, agentKey, agentCerts, share.Id())
	dkg.Threshold = share.Threshold
	return &SchnorrSigningCeremony{
		CloverSchnorrShare: share,
		Dkg:                &dkg,
	}
}

func (sc *SchnorrSigningCeremony) PublicKey() *crypto.ECPoint {
	return sc.CloverSchnorrShare.Vs[0]
}

func (sc *SchnorrSigningCeremony) R() *crypto.ECPoint {
	return sc.Dkg.GetPublicKey()
}

func (sc *SchnorrSigningCeremony) Round1(round0 *thresholdagent.SchnorrRound0Msg) (*thresholdagent.SchnorrRound1Msg, error) {
	sc.Round0 = round0
	return sc.Dkg.Round1(round0)
}

func (sc *SchnorrSigningCeremony) Round2(round1 ...*thresholdagent.SchnorrRound1Msg) ([]*thresholdagent.SchnorrRound2Msg, error) {
	return sc.Dkg.Round2(round1...)
}

func (sc *SchnorrSigningCeremony) Round3(round2 ...*thresholdagent.SchnorrRound2Msg) (*thresholdagent.SchnorrRound3Msg, error) {
	_, err := sc.Dkg.Round3(round2...)
	if err != nil {
		return nil, err
	}
	r_i := sc.Dkg.Share.Share
	var msg [32]byte
	copy(msg[:], sc.Round0.GetSigning().GetMessage())
	k := thresholdagent.GetScalar(sc.Round0.SType, msg, sc.R().X().Bytes(), sc.PublicKey())

	sigma_i := new(big.Int).Mul(k, sc.Share.Share)
	sigma_i = new(big.Int).Add(sigma_i, r_i)
	sigma_i = new(big.Int).Mod(sigma_i, tss.EC().Params().N)

	sc.sigma_i = sigma_i
	return &thresholdagent.SchnorrRound3Msg{
		SessionId: sc.Dkg.SessionId,
		SenderId:  sc.Dkg.Id(),
		Data: &thresholdagent.SchnorrRound3Msg_SigmaI{
			SigmaI: sigma_i.Bytes(),
		},
	}, nil
}

func (sc *SchnorrSigningCeremony) Round4(round3 ...*thresholdagent.SchnorrRound3Msg) (*thresholdagent.SchnorrSignature, error) {
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
	R := sc.Dkg.GetPublicKey()
	sgn := &thresholdagent.SchnorrSignature{
		SType:       sc.Round0.SType,
		PublicKey:   sc.GetCompressedPublicKey(),
		SigningData: sc.Round0.GetSigning().GetMessage(),
		R:           R.X().Bytes(),
		S:           s.Bytes(),
	}
	if !sgn.Verify() {
		return nil, fmt.Errorf("the computed signature is not valid")
	}
	//verify signature
	return sgn, nil
}
func FilterRound3(id int32, roundx []*thresholdagent.SchnorrRound3Msg) []*thresholdagent.SchnorrRound3Msg {
	var result []*thresholdagent.SchnorrRound3Msg
	for _, next := range roundx {
		if next.SenderId != id {
			result = append(result, next)
		}
	}
	return result
}
