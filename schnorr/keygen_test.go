package schnorr

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/clover-network/threshold-crypto/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKeyGen(t *testing.T) {
	var agentKeys = make(map[int]*ecdsa.PrivateKey)
	var agentCerts = make(map[int]*x509.Certificate)

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

	ids := [5]int{1, 2, 3, 4, 5}
	players := make([]KeyGen, len(ids))
	threshold := 3
	for i := 0; i < len(players); i++ {
		players[i] = NewKeyGen(agentKeys[i+1], agentCerts, "session 1", ids[i], threshold)
	}
	var err error
	roun1x := make([]*Round1Message, len(ids))
	for i := 0; i < len(players); i++ {
		roun1x[i], err = players[i].Round1(ids[:])
		assert.Nil(t, err)
	}

	roun2x := make([][]*Round2Message, len(ids))
	for i := 0; i < len(players); i++ {
		roun2x[i], err = players[i].Round2(filter(int(players[i].ID.Int64()), roun1x)...)
		assert.Nil(t, err)
	}

	roun3x := make([]*Round3Message, len(ids))
	for i := 0; i < len(players); i++ {
		roun3x[i], err = players[i].Round3(filter2(int(players[i].ID.Int64()), roun2x)...)
		assert.Nil(t, err)
		players[i].WriteToFile()
	}

	secret, _ := utils.ReConstructSecret(players[0].Share, players[1].Share, players[2].Share, players[3].Share)
	computedPubkey := crypto.ScalarBaseMult(tss.EC(), secret)
	assert.Equal(t, players[0].GetPublicKey(), computedPubkey)

}

func filter2(id int, roundx [][]*Round2Message) []*Round2Message {
	var result []*Round2Message
	for _, line := range roundx {
		for _, next := range line {
			if next.ReceiverId == id && next.SenderId != id {
				result = append(result, next)
			}
		}
	}
	return result
}
func filter(id int, roundx []*Round1Message) []*Round1Message {
	var result []*Round1Message
	for _, next := range roundx {
		if next.SenderId != id {
			result = append(result, next)
		}
	}
	return result
}
