package encrypting

import (
	"github.com/clover-network/threshold-crypto/utils"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestSEncryptDecrypt(t *testing.T) {
	var agentACert, err = utils.LoadCertificateFromFilePath("../cert-files/agents/agent_1.cert")
	require.Nil(t, err)

	var agentAKey, err1 = utils.LoadPrivateKeyPemFilePath("", "../cert-files/agents/agent_1.key")
	require.Nil(t, err1)

	var agentBCert, err2 = utils.LoadCertificateFromFilePath("../cert-files/agents/agent_2.cert")
	require.Nil(t, err2)

	var agentBKey, err3 = utils.LoadPrivateKeyPemFilePath("", "../cert-files/agents/agent_2.key")
	require.Nil(t, err3)

	var message = "MSK-hello world with stkr! hello world with stkr! hello world with stkr! hello world with stkr! hello world with stkr!-SK"

	var encrypted, _ = Encrypt(agentAKey, agentACert, agentBCert, message)

	var recovered, _ = Decrypt(agentBKey, agentACert, encrypted)

	require.True(t, strings.Compare(message, string(recovered)) == 0)

}
