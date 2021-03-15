package schnorr

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/clover-network/threshold-crypto/thresholdagent"
	"github.com/clover-network/threshold-crypto/utils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSigning(t *testing.T) {
	var agentKeys = make(map[int32]*ecdsa.PrivateKey)
	var agentCerts = make(map[int32]*x509.Certificate)

	agentCerts[1], _ = utils.LoadCertificateFromFilePath("../shares/agent1.cert")
	agentCerts[2], _ = utils.LoadCertificateFromFilePath("../shares/agent2.cert")
	agentCerts[3], _ = utils.LoadCertificateFromFilePath("../shares/agent3.cert")
	agentCerts[4], _ = utils.LoadCertificateFromFilePath("../shares/agent4.cert")
	//agentCerts[5], _ = utils.LoadCertificateFromFilePath("../shares/agent5.cert")

	agentKeys[1], _ = utils.LoadPrivateKeyPemFilePath("", "../shares/agent1.key")
	agentKeys[2], _ = utils.LoadPrivateKeyPemFilePath("", "../shares/agent2.key")
	agentKeys[3], _ = utils.LoadPrivateKeyPemFilePath("", "../shares/agent3.key")
	agentKeys[4], _ = utils.LoadPrivateKeyPemFilePath("", "../shares/agent4.key")
	//agentKeys[5], _ = utils.LoadPrivateKeyPemFilePath("","../shares/agent5.key")

	ids := []int32{1, 2, 3, 4} //16
	message := []byte{5, 4, 7, 6}

	signers := make([]*SchnorrSigningCeremony, len(ids))
	for i := 0; i < len(ids); i++ {
		sc := &CloverSchnorrShare{}
		sc.ReadFromFile(ids[i])
		signers[i] = NewSchnorrSigningCeremony(agentKeys[ids[i]], agentCerts, sc)
	}

	var err error
	roun1x := make([]*thresholdagent.SchnorrRound1Msg, len(ids))
	for i := 0; i < len(signers); i++ {
		roun1x[i], err = signers[i].Round1(&thresholdagent.SchnorrRound0Msg{
			SessionId: "session 1",
			SType:     thresholdagent.SignatureType_SCHNORRv1,
			Ids:       ids,
			Message:   message,
		})
		assert.Nil(t, err)
	}

	roun2x := make([][]*thresholdagent.SchnorrRound2Msg, len(ids))
	for i := 0; i < len(signers); i++ {
		roun2x[i], err = signers[i].Round2(filter(int32(signers[i].ID.Int64()), roun1x)...)
		assert.Nil(t, err)
	}

	roun3x := make([]*thresholdagent.SchnorrRound3Msg, len(ids))
	for i := 0; i < len(signers); i++ {
		roun3x[i], err = signers[i].Round3(filter2(int32(signers[i].ID.Int64()), roun2x)...)
		assert.Nil(t, err)
	}
	roun4x := make([]*thresholdagent.SchnorrSignature, len(ids))
	for i := 0; i < len(signers); i++ {
		roun4x[i], err = signers[i].Round4(filter3i(int32(signers[i].ID.Int64()), roun3x)...)
		assert.Nil(t, err)
		assert.True(t, Verify(signers[i].round0.SType, roun4x[i], message, signers[i].PublicKey()))
	}
}
func filter3i(id int32, roundx []*thresholdagent.SchnorrRound3Msg) []*thresholdagent.SchnorrRound3Msg {
	var result []*thresholdagent.SchnorrRound3Msg
	for _, next := range roundx {
		if next.SenderId != id {
			result = append(result, next)
		}
	}
	return result
}
