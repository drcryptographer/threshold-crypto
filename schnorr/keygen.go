package schnorr

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/clover-network/threshold-crypto/encrypting"
	"github.com/clover-network/threshold-crypto/feldmanvss"
	"github.com/clover-network/threshold-crypto/thresholdagent"
	"github.com/clover-network/threshold-crypto/utils"
	"io/ioutil"
	"math/big"
)

type CloverSchnorrShare struct {
	vss.Vs
	vss.Share
}

func (cs *CloverSchnorrShare) ReadFromFile(id int32) error {
	buffer, _ := ioutil.ReadFile(fmt.Sprintf("../shares/schnorr_share_%d.json", id))
	return json.Unmarshal(buffer, cs)
}

func (cs *CloverSchnorrShare) Id() int32 {
	return int32(cs.ID.Int64())
}

type SchnorrKeyGen struct {
	SessionId string
	*vss.Share
	poly           vss.Vs
	simPoly        vss.Vs
	shares         map[int32]*vss.Share
	simShares      map[int32]*vss.Share
	round1Messages map[int32]*thresholdagent.SchnorrRound1Msg
	round2Messages map[int32]*thresholdagent.SchnorrRound2Msg

	agentKey   *ecdsa.PrivateKey
	agentCerts map[int32]*x509.Certificate
	caCert     *x509.Certificate
	round0     *thresholdagent.SchnorrRound0Msg
}

func NewSchnorrKeyGen(caCert *x509.Certificate, agentKey *ecdsa.PrivateKey, agentCerts map[int32]*x509.Certificate, id int32, threshold int) SchnorrKeyGen {
	return SchnorrKeyGen{
		Share: &vss.Share{
			Threshold: threshold,
			ID:        big.NewInt(int64(id)),
			Share:     big.NewInt(0),
		},
		shares:         make(map[int32]*vss.Share),
		simShares:      make(map[int32]*vss.Share),
		round1Messages: make(map[int32]*thresholdagent.SchnorrRound1Msg),
		round2Messages: make(map[int32]*thresholdagent.SchnorrRound2Msg),
		agentKey:       agentKey,
		agentCerts:     agentCerts,
		caCert:         caCert,
	}
}
func (kg *SchnorrKeyGen) GetCertificate() *x509.Certificate {
	return kg.agentCerts[kg.Id()]
}
func (kg *SchnorrKeyGen) GetSecretShare() *CloverSchnorrShare {
	return &CloverSchnorrShare{
		Vs:    kg.poly,
		Share: *kg.Share,
	}
}
func (kg *SchnorrKeyGen) GetPublicKey() *crypto.ECPoint {
	return kg.poly[0]
}

func (kg *SchnorrKeyGen) WriteToFile() {
	result := kg.GetSecretShare()
	buffer, _ := json.Marshal(&result)
	ioutil.WriteFile(fmt.Sprintf("../shares/schnorr_share_%d.json", kg.Id()), buffer, 0644)
}

func (kg *SchnorrKeyGen) Id() int32 {
	return int32(kg.ID.Int64())
}

//initialize polynomial and simulated polynomial
//commit on the summation of two polynomial
func (kg *SchnorrKeyGen) Round1(round0 *thresholdagent.SchnorrRound0Msg) (*thresholdagent.SchnorrRound1Msg, error) {
	//we assume that each certificate has common name with "agent={Id}"
	kg.round0 = round0
	ids2 := make([]*big.Int, len(round0.SignerCerts))
	for i := 0; i < len(ids2); i++ {
		cert, _ := utils.ParseCertificate(round0.SignerCerts[i])
		if !utils.VerifyCert(cert, kg.caCert) {
			return nil, fmt.Errorf("not verified certificate [%s]", cert.Subject.CommonName)
		}
		var id = utils.GetId(cert)
		if id < 1 {
			return nil, fmt.Errorf("not valid agent id of certificate [%s]", cert.Subject.CommonName)
		}
		ids2[i] = big.NewInt(int64(id))
	}
	var order = tss.EC().Params().N

	secret := common.GetRandomPositiveInt(order)
	simSecret := common.GetRandomPositiveInt(order)

	poly, shares, _ := vss.Create(kg.Threshold, secret, ids2)
	kg.poly = poly
	for _, next := range shares {
		kg.shares[int32(next.ID.Int64())] = next
	}
	//commitment should be on H not on G
	simPoly, simShares, _ := vss.Create(kg.Threshold, simSecret, ids2)
	kg.simPoly = simPoly
	for _, next := range simShares {
		kg.simShares[int32(next.ID.Int64())] = next
	}

	commitment, err := feldmanvss.AddVs(kg.simPoly, kg.poly)
	if err != nil {
		return nil, err
	}
	buffer, err := json.Marshal(&commitment)
	if err != nil {
		return nil, err
	}
	kg.round1Messages[kg.Id()] = &thresholdagent.SchnorrRound1Msg{
		SessionId:  kg.SessionId,
		SenderId:   int32(kg.ID.Int64()),
		Commitment: buffer,
	}
	return kg.round1Messages[kg.Id()], nil
}

func (kg *SchnorrKeyGen) Round2(round1s ...*thresholdagent.SchnorrRound1Msg) ([]*thresholdagent.SchnorrRound2Msg, error) {
	if len(round1s)+1 < kg.Share.Threshold {
		return nil, fmt.Errorf("not enough round 1 messages")
	}
	for i := 0; i < len(round1s); i++ {
		kg.round1Messages[round1s[i].SenderId] = round1s[i]
	}
	var roun2msgs []*thresholdagent.SchnorrRound2Msg
	poly, err := json.Marshal(&kg.poly)
	if err != nil {
		return nil, err
	}
	for i, next := range kg.shares {
		if kg.ID.Cmp(next.ID) == 0 {
			kg.Share.Share = next.Share
			continue
		}
		var encryptedKey, _ = encrypting.Encrypt(kg.agentKey, kg.agentCerts[kg.Id()], kg.agentCerts[int32(next.ID.Int64())], utils.ToBytes(next))
		var encryptedSimulatedShareKey, _ = encrypting.Encrypt(kg.agentKey, kg.agentCerts[kg.Id()], kg.agentCerts[int32(next.ID.Int64())], utils.ToBytes(kg.simShares[i]))

		roun2msgs = append(roun2msgs, &thresholdagent.SchnorrRound2Msg{
			SessionId:         kg.SessionId,
			SenderId:          kg.Id(),
			ReceiverId:        int32(next.ID.Int64()),
			ShareKey:          encryptedKey,               //encrypt it
			SimulatedShareKey: encryptedSimulatedShareKey, //encrypt it
			Poly:              poly,
		})
	}
	return roun2msgs, nil
}

func (kg *SchnorrKeyGen) Round3(round2s ...*thresholdagent.SchnorrRound2Msg) (*thresholdagent.SchnorrRound3Msg, error) {
	if len(round2s)+1 < kg.Threshold {
		return nil, fmt.Errorf("not enough round 1 messages")
	}
	for i := 0; i < len(round2s); i++ {
		kg.round2Messages[round2s[i].SenderId] = round2s[i]
	}

	poly := kg.poly
	share := kg.shares[kg.Id()]
	simShare := kg.simShares[kg.Id()]
	for _, next := range round2s {
		nPoly, _ := utils.ParsePoly(next.Poly)
		poly, _ = feldmanvss.AddVs(poly, nPoly)

		decryptedKey, _ := encrypting.Decrypt(kg.agentKey, kg.agentCerts[next.SenderId], next.ShareKey)
		nShare, _ := utils.ParseShare(decryptedKey)
		share, _ = feldmanvss.AddShare(share, nShare)

		decryptedsimKey, _ := encrypting.Decrypt(kg.agentKey, kg.agentCerts[next.SenderId], next.SimulatedShareKey)
		nShare, _ = utils.ParseShare(decryptedsimKey)
		simShare, _ = feldmanvss.AddShare(simShare, nShare)
	}
	if !share.Verify(kg.Threshold, poly) {
		return nil, fmt.Errorf("keyshare is not verified")
	}

	sumShare, _ := feldmanvss.AddShare(simShare, share)
	//sum commitment
	var sumCommitment vss.Vs
	for _, next := range kg.round1Messages {
		nextCom, _ := utils.ParsePoly(next.Commitment)
		if sumCommitment == nil {
			sumCommitment = nextCom
		} else {
			sumCommitment, _ = feldmanvss.AddVs(sumCommitment, nextCom)
		}
	}
	if !sumShare.Verify(kg.Threshold, sumCommitment) {
		return nil, fmt.Errorf("sumshare is not verified")
	}
	kg.Share = share
	kg.poly = poly

	//decrypt share
	//verify share
	//sum share
	//calculate public key
	//store share
	pubkey, _ := poly[0].GobEncode()
	return &thresholdagent.SchnorrRound3Msg{
		SessionId: kg.SessionId,
		SenderId:  kg.Id(),
		Data: &thresholdagent.SchnorrRound3Msg_PublicKey{
			PublicKey: pubkey,
		},
	}, nil
}

func print(data interface{}) {
	buffer, _ := json.Marshal(&data)
	println(string(buffer))
}
