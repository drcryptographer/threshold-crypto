package schnorr

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/clover-network/threshold-crypto/thresholdagent"
	"github.com/clover-network/threshold-crypto/utils"
	"github.com/fiatjaf/bip340"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestMulSigningOfSignatureType_SCHNORRv2(t *testing.T) {
	for i := 0; i < 10; i++ {
		fmt.Printf("Test %d\n", i+1)
		RunTestSigning(t, thresholdagent.SignatureType_SCHNORRv2)
	}
}

func TestMulSigningOfSignatureType_SCHNORRv1(t *testing.T) {
	for i := 0; i < 100; i++ {
		fmt.Printf("Test %d\n", i+1)
		RunTestSigning(t, thresholdagent.SignatureType_SCHNORRv1)
	}
} //false-true ok,
// true/true ok
// false/false not ok
//true/false not ok
func RunTestSigning(t *testing.T, sType thresholdagent.SignatureType) {
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

	var signerCerts = make([][]byte, 4)

	signerCerts[0], _ = ioutil.ReadFile("../shares/agent1.cert")
	signerCerts[1], _ = ioutil.ReadFile("../shares/agent2.cert")
	signerCerts[2], _ = ioutil.ReadFile("../shares/agent3.cert")
	signerCerts[3], _ = ioutil.ReadFile("../shares/agent4.cert")

	//test
	var caCert, _ = utils.LoadCertificateFromFilePath("../shares/ca.cert")

	ids := []int32{1, 2, 3, 4} //16

	hash := sha256.New()
	hash.Write([]byte{5, 4, 7, 6})
	message := hash.Sum(nil)

	signers := make([]*SchnorrSigningCeremony, len(ids))
	for i := 0; i < len(ids); i++ {
		sc := &CloverSchnorrShare{}
		sc.ReadFromFile(ids[i])
		signers[i] = NewSchnorrSigningCeremony("session 1", caCert, agentKeys[ids[i]], agentCerts, sc)
	}

	var err error
	roun1x := make([]*thresholdagent.SchnorrRound1Msg, len(ids))
	for i := 0; i < len(signers); i++ {
		roun1x[i], err = signers[i].Round1(&thresholdagent.SchnorrRound0Msg{
			SessionId:   "session 1",
			SType:       sType,
			SignerCerts: signerCerts,
			Request: &thresholdagent.SchnorrRound0Msg_Signing{
				Signing: &thresholdagent.SignRequest{
					PublicKey: nil,
					Message:   message,
				},
			},
		})
		assert.Nil(t, err)
	}

	roun2x := make([][]*thresholdagent.SchnorrRound2Msg, len(ids))
	for i := 0; i < len(signers); i++ {
		roun2x[i], err = signers[i].Round2(FilterRound1(int32(signers[i].ID.Int64()), roun1x)...)
		assert.Nil(t, err)
	}

	roun3x := make([]*thresholdagent.SchnorrRound3Msg, len(ids))
	for i := 0; i < len(signers); i++ {
		roun3x[i], err = signers[i].Round3(FilterRound2(int32(signers[i].ID.Int64()), roun2x)...)
		assert.Nil(t, err)
	}
	roun4x := make([]*thresholdagent.SchnorrSignature, len(ids))
	for i := 0; i < len(signers); i++ {
		roun4x[i], err = signers[i].Round4(FilterRound3(int32(signers[i].ID.Int64()), roun3x)...)
		assert.Nil(t, err)
		assert.True(t, roun4x[i].Verify())

		if roun4x[0].SType == thresholdagent.SignatureType_SCHNORRv1 {
			var (
				publicKey [32]byte
				message   [32]byte
				signature [64]byte
			)
			copy(publicKey[:], roun4x[0].CompressedPublicKey[1:])
			copy(message[:], roun4x[0].SigningData)
			copy(signature[:32], roun4x[0].R)
			copy(signature[32:], roun4x[0].S)

			result, _ := bip340.Verify(publicKey, message, signature)
			assert.True(t, result)
		}
		//
	}
}
