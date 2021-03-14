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
	"github.com/clover-network/threshold-crypto/utils"
	"io/ioutil"
	"math/big"
)

type Round1Message struct {
	SessionId  string
	SenderId   int
	Commitment []byte
}

type Round2Message struct {
	SessionId         string
	SenderId          int
	ReceiverId        int
	ShareKey          []byte
	SimulatedShareKey []byte
	Poly              []byte
}

type Round3Message struct {
	SessionId string
	SenderId  int
	PublicKey []byte
}

type CloverShare struct {
	vss.Vs
	vss.Share
}

func (cs *CloverShare) ReadFromFile(id int) error {
	buffer, _ := ioutil.ReadFile(fmt.Sprintf("../shares/share_%d.json", id))
	return json.Unmarshal(buffer, cs)
}

type KeyGen struct {
	SessionId string
	*vss.Share
	poly           vss.Vs
	simPoly        vss.Vs
	shares         map[int]*vss.Share
	simShares      map[int]*vss.Share
	round1Messages map[int]*Round1Message
	round2Messages map[int]*Round2Message

	agentKey   *ecdsa.PrivateKey
	agentCerts map[int]*x509.Certificate
	caCert     *x509.Certificate
}

func NewKeyGen(agentKey *ecdsa.PrivateKey, agentCerts map[int]*x509.Certificate, SessionId string, id, threshold int) KeyGen {
	return KeyGen{
		SessionId: SessionId,
		Share: &vss.Share{
			Threshold: threshold,
			ID:        big.NewInt(int64(id)),
			Share:     big.NewInt(0),
		},
		shares:         make(map[int]*vss.Share),
		simShares:      make(map[int]*vss.Share),
		round1Messages: make(map[int]*Round1Message),
		round2Messages: make(map[int]*Round2Message),
		agentKey:       agentKey,
		agentCerts:     agentCerts,
	}
}
func (kg *KeyGen) GetCertificate() *x509.Certificate {
	return kg.agentCerts[kg.Id()]
}
func (kg *KeyGen) GetSecretShare() *CloverShare {
	return &CloverShare{
		Vs:    kg.poly,
		Share: *kg.Share,
	}
}
func (kg *KeyGen) GetPublicKey() *crypto.ECPoint {
	return kg.poly[0]
}

func (kg *KeyGen) WriteToFile() {
	result := kg.GetSecretShare()
	buffer, _ := json.Marshal(&result)
	ioutil.WriteFile(fmt.Sprintf("../shares/share_%d.json", kg.Id()), buffer, 0644)
}

func (kg *KeyGen) Id() int {
	return int(kg.ID.Int64())
}
func (kg *KeyGen) Round3(round2s ...*Round2Message) (*Round3Message, error) {
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
	return &Round3Message{
		SessionId: kg.SessionId,
		SenderId:  kg.Id(),
		PublicKey: pubkey,
	}, nil
}

func (kg *KeyGen) Round2(round1s ...*Round1Message) ([]*Round2Message, error) {
	if len(round1s)+1 < kg.Share.Threshold {
		return nil, fmt.Errorf("not enough round 1 messages")
	}
	for i := 0; i < len(round1s); i++ {
		kg.round1Messages[round1s[i].SenderId] = round1s[i]
	}
	var roun2msgs []*Round2Message
	poly, err := json.Marshal(&kg.poly)
	if err != nil {
		return nil, err
	}
	for i, next := range kg.shares {
		if kg.ID.Cmp(next.ID) == 0 {
			kg.Share.Share = next.Share
			continue
		}
		var encryptedKey, _ = encrypting.Encrypt(kg.agentKey, kg.agentCerts[kg.Id()], kg.agentCerts[int(next.ID.Int64())], utils.ToBytes(next))
		var encryptedSimulatedShareKey, _ = encrypting.Encrypt(kg.agentKey, kg.agentCerts[kg.Id()], kg.agentCerts[int(next.ID.Int64())], utils.ToBytes(kg.simShares[i]))

		roun2msgs = append(roun2msgs, &Round2Message{
			SessionId:         kg.SessionId,
			SenderId:          kg.Id(),
			ReceiverId:        int(next.ID.Int64()),
			ShareKey:          encryptedKey,               //encrypt it
			SimulatedShareKey: encryptedSimulatedShareKey, //encrypt it
			Poly:              poly,
		})
	}
	return roun2msgs, nil
}

//initialize polynomial and simulated polynomial
//commit on the summation of two polynomial
func (kg *KeyGen) Round1(ids []int) (*Round1Message, error) {
	ids2 := make([]*big.Int, len(ids))
	for i := 0; i < len(ids); i++ {
		ids2[i] = big.NewInt(int64(ids[i]))
	}
	order := tss.EC().Params().N

	secret := common.GetRandomPositiveInt(order)
	simSecret := common.GetRandomPositiveInt(order)

	poly, shares, _ := vss.Create(kg.Threshold, secret, ids2)
	kg.poly = poly
	for _, next := range shares {
		kg.shares[int(next.ID.Int64())] = next
	}
	//commitment should be on H not on G
	simPoly, simShares, _ := vss.Create(kg.Threshold, simSecret, ids2)
	kg.simPoly = simPoly
	for _, next := range simShares {
		kg.simShares[int(next.ID.Int64())] = next
	}

	commitment, err := feldmanvss.AddVs(kg.simPoly, kg.poly)
	if err != nil {
		return nil, err
	}
	buffer, err := json.Marshal(&commitment)
	if err != nil {
		return nil, err
	}
	kg.round1Messages[kg.Id()] = &Round1Message{
		SessionId:  kg.SessionId,
		SenderId:   int(kg.ID.Int64()),
		Commitment: buffer,
	}
	return kg.round1Messages[kg.Id()], nil
}
func print(data interface{}) {
	buffer, _ := json.Marshal(&data)
	println(string(buffer))
}