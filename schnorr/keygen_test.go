package schnorr

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/clover-network/threshold-crypto/thresholdagent"
	"github.com/clover-network/threshold-crypto/utils"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestKeyGen(t *testing.T) {
	var agentKeys = make(map[int32]*ecdsa.PrivateKey)
	var agentCerts = make(map[int32]*x509.Certificate)

	var signerCerts = make([][]byte, 5)

	agentCerts[1], _ = utils.LoadCertificateFromFilePath("../shares/agent1.cert")
	agentCerts[2], _ = utils.LoadCertificateFromFilePath("../shares/agent2.cert")
	agentCerts[3], _ = utils.LoadCertificateFromFilePath("../shares/agent3.cert")
	agentCerts[4], _ = utils.LoadCertificateFromFilePath("../shares/agent4.cert")
	agentCerts[5], _ = utils.LoadCertificateFromFilePath("../shares/agent5.cert")

	agentKeys[1], _ = utils.LoadPrivateKeyPemFilePath("", "../shares/agent1.key")
	agentKeys[2], _ = utils.LoadPrivateKeyPemFilePath("", "../shares/agent2.key")
	agentKeys[3], _ = utils.LoadPrivateKeyPemFilePath("", "../shares/agent3.key")
	agentKeys[4], _ = utils.LoadPrivateKeyPemFilePath("", "../shares/agent4.key")
	agentKeys[5], _ = utils.LoadPrivateKeyPemFilePath("", "../shares/agent5.key")

	//
	signerCerts[0], _ = ioutil.ReadFile("../shares/agent1.cert")
	signerCerts[1], _ = ioutil.ReadFile("../shares/agent2.cert")
	signerCerts[2], _ = ioutil.ReadFile("../shares/agent3.cert")
	signerCerts[3], _ = ioutil.ReadFile("../shares/agent4.cert")
	signerCerts[4], _ = ioutil.ReadFile("../shares/agent5.cert")

	var caCert, _ = utils.LoadCertificateFromFilePath("../shares/ca.cert")

	ids := [5]int32{1, 2, 3, 4, 5}
	players := make([]SchnorrKeyGen, len(ids))
	threshold := 3
	for i := 0; i < len(players); i++ {
		players[i] = NewSchnorrKeyGen(caCert, agentKeys[int32(i+1)], agentCerts, ids[i], threshold)
	}
	var err error
	roun1x := make([]*thresholdagent.SchnorrRound1Msg, len(ids))
	for i := 0; i < len(players); i++ {
		roun1x[i], err = players[i].Round1(&thresholdagent.SchnorrRound0Msg{
			SessionId:   "session 1",
			SType:       thresholdagent.SignatureType_SCHNORRv1,
			SignerCerts: signerCerts,
		})
		assert.Nil(t, err)
	}

	roun2x := make([][]*thresholdagent.SchnorrRound2Msg, len(ids))
	for i := 0; i < len(players); i++ {
		roun2x[i], err = players[i].Round2(filter(int32(players[i].ID.Int64()), roun1x)...)
		assert.Nil(t, err)
	}

	roun3x := make([]*thresholdagent.SchnorrRound3Msg, len(ids))
	for i := 0; i < len(players); i++ {
		roun3x[i], err = players[i].Round3(filter2(int32(players[i].ID.Int64()), roun2x)...)
		assert.Nil(t, err)
		players[i].WriteToFile()
	}

	secret, _ := utils.ReConstructSecret(players[0].Share, players[1].Share, players[2].Share, players[3].Share)
	computedPubkey := crypto.ScalarBaseMult(tss.EC(), secret)
	assert.Equal(t, players[0].GetPublicKey(), computedPubkey)

}

func filter2(id int32, roundx [][]*thresholdagent.SchnorrRound2Msg) []*thresholdagent.SchnorrRound2Msg {
	var result []*thresholdagent.SchnorrRound2Msg
	for _, line := range roundx {
		for _, next := range line {
			if next.ReceiverId == id && next.SenderId != id {
				result = append(result, next)
			}
		}
	}
	return result
}
func filter(id int32, roundx []*thresholdagent.SchnorrRound1Msg) []*thresholdagent.SchnorrRound1Msg {
	var result []*thresholdagent.SchnorrRound1Msg
	for _, next := range roundx {
		if next.SenderId != id {
			result = append(result, next)
		}
	}
	return result
}
