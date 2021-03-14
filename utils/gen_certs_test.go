package utils

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strconv"
	"testing"
)

var RootPassword = "clover!Test!123456"

func TestCreateCertificates(t *testing.T) {
	root, _ := CreateCARoot(RootPassword, "Clover Finance ROOT CA", "China", "CH", "Clover Finance", "CLV", 20, 545455454)

	err := ioutil.WriteFile("../shares/ca.key", []byte(root.PrivateKeyPem), 0644)
	assert.Nil(t, err)

	err = ioutil.WriteFile("../shares/ca.cert", []byte(root.SignedCertPem), 0644)
	assert.Nil(t, err)

	err = CreateWriteCertificate(5)
	assert.Nil(t, err)
}

func TestVerifyCertificate(t *testing.T) {
	var rootSignedCertPem, _ = ioutil.ReadFile("../shares/ca.cert")
	//caKey, _ := LoadPrivateKeyFromFile(RootPassword,"../shares/ca.key")
	//print(caKey.X)
	caCert, _ := ParseCertificate(rootSignedCertPem)
	agentCert, _ := LoadCertFromFile("../shares/agent1.cert")
	assert.True(t, VerifyCert(agentCert, caCert))
}
func LoadPrivateKeyFromFile(password, filename string) (*ecdsa.PrivateKey, error) {
	var agentKeyByte, _ = ioutil.ReadFile(filename)
	return ParseCertificateKeyPem(password, agentKeyByte)
}
func LoadCertFromFile(filename string) (*x509.Certificate, error) {
	var agentCertByte, _ = ioutil.ReadFile(filename)
	return ParseCertificate(agentCertByte)
}

func TestGetId(t *testing.T) {
	for i := 1; i <= 5; i++ {
		var agentCertByte, _ = ioutil.ReadFile(fmt.Sprintf("../shares/agent%d.cert", i))
		agentCert, _ := ParseCertificate(agentCertByte)
		assert.Equal(t, i, GetId(agentCert))
	}
}

func CreateWriteCertificate(totalPlayer int) error {
	var dnsNames = []string{"localhost"}

	var rootPrivateKeyPem, _ = ioutil.ReadFile("../shares/ca.key")
	var rootSignedCertPem, _ = ioutil.ReadFile("../shares/ca.cert")
	for i := 0; i < totalPlayer; i++ {
		var certAgent, err = CreatePlainServerCert(RootPassword, rootPrivateKeyPem, rootSignedCertPem,
			fmt.Sprintf("agent=%d", (i+1)), "US", "SF", "Clover Finance", "CLV",
			dnsNames, []string{"0.0.0.0", "127.0.0.1"}, 20, i+1)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile("../shares/agent"+strconv.Itoa(i+1)+".key", []byte(certAgent.PrivateKeyPem), 0644)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile("../shares/agent"+strconv.Itoa(i+1)+".cert", []byte(certAgent.SignedCertPem), 0644)
		if err != nil {
			return err
		}
	}
	return nil
}
