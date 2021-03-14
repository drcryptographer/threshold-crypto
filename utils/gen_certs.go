package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

type CertificateAsPem struct {
	SignedCertPem string
	PrivateKeyPem string
}

func LoadCertificateFromFilePath(certFilePath string) (*x509.Certificate, error) {
	var buffer, err = ioutil.ReadFile(certFilePath)
	if err != nil {
		return nil, err
	}
	return ParseCertificate(buffer)
}
func LoadPrivateKeyPemFilePath(password, keyFilePath string) (*ecdsa.PrivateKey, error) {
	var buffer, err = ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}
	return ParseCertificateKeyPem(password, buffer)
}

func ParseCertificateKeyPem(password string, certKeyPEM []byte) (*ecdsa.PrivateKey, error) {
	var keyBlock *pem.Block
	var rest = certKeyPEM
	for {
		keyBlock, rest = pem.Decode(rest)
		if strings.Compare(keyBlock.Type, "EC PRIVATE KEY") == 0 {
			break
		}
		if len(rest) == 0 {
			return nil, fmt.Errorf("corrupted certificate key pem")
		}
	}
	if keyBlock == nil {
		return nil, fmt.Errorf("corrupted certificate key pem")
	}
	if x509.IsEncryptedPEMBlock(keyBlock) {
		var decryptedKey, err = x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("Invalid Password or Corrupted Ciphertext")
		}
		return x509.ParseECPrivateKey(decryptedKey)
	}
	return x509.ParseECPrivateKey(keyBlock.Bytes)
}
func ParseCertificate(certPEM []byte) (*x509.Certificate, error) {
	var block, _ = pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("corrupted certificate")
	}
	var cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func VerifyCertificate(childCertPem, rootCertPem []byte) bool {

	var rootCert, err = ParseCertificate(rootCertPem)
	if err != nil {
		return false
	}
	var childCert, err2 = ParseCertificate(childCertPem)
	if err2 != nil {
		return false
	}

	return VerifyCert(childCert, rootCert)
}

func GetId(cert *x509.Certificate) int {
	result, _ := strconv.Atoi(string([]byte(cert.Subject.CommonName)[6:]))
	return result
}
func VerifyCert(childCert, rootCert *x509.Certificate) bool {
	var roots = x509.NewCertPool()
	roots.AddCert(rootCert)
	var opts = x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := childCert.Verify(opts); err != nil {
		return false
	}
	return true
}

func CreatePlainServerCert(password string, rootKeyPem []byte, rootCertPem []byte, commonName, country, location, company, ounit string, DNSNames, ipaddress []string, year, serialNumber int) (*CertificateAsPem, error) {
	var rootCert, err = ParseCertificate(rootCertPem)
	if err != nil {
		return nil, err
	}
	//decode root certificate private key
	var rootKey, err2 = ParseCertificateKeyPem(password, rootKeyPem)
	if err2 != nil {
		return nil, err2
	}
	var curve = rootKey.Curve
	var priv, err3 = ecdsa.GenerateKey(curve, rand.Reader)
	if err3 != nil {
		return nil, err3
	}

	var (
		ServerTemplate = x509.Certificate{
			Subject: pkix.Name{
				Country:            []string{country},
				Organization:       []string{company},
				OrganizationalUnit: []string{ounit},
				CommonName:         commonName,
				Locality:           []string{location},
				SerialNumber:       strconv.Itoa(serialNumber),
			},
			SerialNumber: big.NewInt(int64(serialNumber)),
			NotBefore:    time.Now().Add(-10 * time.Second),
			NotAfter:     time.Now().AddDate(year, 0, 0),
			KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IsCA:         false,
		}
	)
	for _, nextDNSName := range DNSNames {
		ServerTemplate.DNSNames = append(ServerTemplate.DNSNames, nextDNSName)
	}
	for _, nextIp := range ipaddress {
		ServerTemplate.IPAddresses = append(ServerTemplate.IPAddresses, net.ParseIP(nextIp))
	}
	secp256r1, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})

	var _, ServerPEM, err4 = genCert(&ServerTemplate, rootCert, &priv.PublicKey, rootKey)
	if err4 != nil {
		return nil, err4
	}
	var x509Encoded, _ = x509.MarshalECPrivateKey(priv)
	var pemEncoded = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded})
	return &CertificateAsPem{
		SignedCertPem: string(ServerPEM),
		PrivateKeyPem: string(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: secp256r1})) + string(pemEncoded),
	}, nil
}
func CreateCARoot(password, commonName, country, location, company, ounit string, year, serial int) (*CertificateAsPem, error) {
	var rootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(int64(serial)),
		Subject: pkix.Name{
			Country:            []string{country},
			Organization:       []string{company},
			OrganizationalUnit: []string{ounit},
			CommonName:         commonName,
			Locality:           []string{location},
			SerialNumber:       strconv.Itoa(serial),
		},
		Issuer: pkix.Name{
			Country:            []string{country},
			Organization:       []string{company},
			CommonName:         commonName,
			OrganizationalUnit: []string{ounit},
			Locality:           []string{location},
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(year, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	var curve = elliptic.P256()
	var priv, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	var _, rootPEM, err2 = genCert(&rootTemplate, &rootTemplate, &priv.PublicKey, priv)
	if err2 != nil {
		return nil, err2
	}
	var x509Encoded, err3 = x509.MarshalECPrivateKey(priv)
	if err3 != nil {
		return nil, err3
	}
	var block *pem.Block
	if password == "" {
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded}
	} else {
		block, _ = x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", x509Encoded, []byte(password), x509.PEMCipherAES256)
	}

	var secp256r1, _ = asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})

	var result = &CertificateAsPem{
		SignedCertPem: string(rootPEM),
		PrivateKeyPem: string(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: secp256r1})) + string(pem.EncodeToMemory(block)),
	}
	return result, nil
}

func genCert(template, parent *x509.Certificate, publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) (*x509.Certificate, []byte, error) {
	var certBytes, err = x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	var cert, err2 = x509.ParseCertificate(certBytes)
	if err2 != nil {
		return nil, nil, err2
	}

	var b = pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	var certPEM = pem.EncodeToMemory(&b)
	return cert, certPEM, nil
}
