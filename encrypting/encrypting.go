package encrypting

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/clover-network/threshold-crypto/utils"
	"io"
	"math/big"
)

type EncryptedMessage struct {
	Rx, Ry *big.Int
	C      string
	E, Z   *big.Int
}

func Decrypt(privB *ecdsa.PrivateKey, certA *x509.Certificate, cipher []byte) ([]byte, error) {

	ciphertext := &EncryptedMessage{}
	json.Unmarshal(cipher, ciphertext)

	pubKeyA := certA.PublicKey.(*ecdsa.PublicKey)
	curve := privB.Curve
	// check first e == H(zG − eA, A, C)
	zG := utils.ScalarECCBaseMult(curve, ciphertext.Z)
	negE := new(big.Int).Mul(ciphertext.E, big.NewInt(-1))
	eA := utils.ScalarECCMult(curve, &utils.Point{
		X: pubKeyA.X,
		Y: pubKeyA.Y,
	}, negE)
	tX, tY := curve.Add(zG.X, zG.Y, eA.X, eA.Y)
	A := new(big.Int).SetBytes([]byte(certA.Subject.CommonName))
	decoded, err := hex.DecodeString(ciphertext.C)
	if err != nil {
		return nil, fmt.Errorf("decrypt-line 71: decode problem %s", err)
	}
	c := new(big.Int).SetBytes(decoded)
	e := utils.ComputeHash256(tX, tY, A, c)

	if e.Cmp(ciphertext.E) != 0 {
		return nil, fmt.Errorf("decrypt-line 77: invalid schnor signature")
	}
	// R' = bR
	//K = H(R').
	RPrime := utils.ScalarECCMult(curve, &utils.Point{
		X: ciphertext.Rx,
		Y: ciphertext.Ry,
	}, privB.D)

	//making 32 byte key length for aes
	key := utils.ComputeHash256(RPrime.X, RPrime.Y).Bytes()
	if len(key) != 32 {
		temp := make([]byte, 32)
		copy(key, temp)
		key = temp
	}

	decoded, err = hex.DecodeString(ciphertext.C)
	if err != nil {
		return nil, fmt.Errorf("decrypt-line 96: decode problem %s", err)
	}
	plaintext, err := decryptAes(decoded, key)
	if err != nil {
		return nil, fmt.Errorf("decrypt-line 100: decrypt problem %s", err)

	}
	//M = Dec_K (C) .
	return plaintext, nil
}
func Encrypt(privA *ecdsa.PrivateKey, certA, certB *x509.Certificate, message []byte) ([]byte, error) {

	publicKeyB := certB.PublicKey.(*ecdsa.PublicKey)

	curve := privA.Curve
	// the order of the base point
	order := privA.Curve.Params().N

	r, err := utils.GetRandomInZnStar(order, rand.Reader)
	if err != nil {
		return nil, err
	}
	s, err2 := utils.GetRandomInZnStar(order, rand.Reader)
	if err2 != nil {
		return nil, err
	}
	R := utils.ScalarECCBaseMult(curve, r) //R=rG
	//R'=rB
	RPrime := utils.ScalarECCMult(curve, &utils.Point{
		X: publicKeyB.X,
		Y: publicKeyB.Y,
	}, r)
	//S = sG
	S := utils.ScalarECCBaseMult(curve, s)

	//making 32 byte key length for aes
	key := utils.ComputeHash256(RPrime.X, RPrime.Y).Bytes()
	if len(key) != 32 {
		temp := make([]byte, 32)
		copy(key, temp)
		key = temp
	}
	C, err := encryptAes([]byte(message), key)
	if err != nil {
		return nil, err
	}

	A := new(big.Int).SetBytes([]byte(certA.Subject.CommonName))
	c := new(big.Int).SetBytes(C)

	e := utils.ComputeHash256(S.X, S.Y, A, c)

	z := new(big.Int).Mul(privA.D, e)
	z.Add(z, s)
	z.Mod(z, curve.Params().N)

	return json.Marshal(&EncryptedMessage{Rx: R.X, Ry: R.Y, C: hex.EncodeToString(C), E: e, Z: z})
}

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func encryptAes(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func decryptAes(data []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}
	var block cipher.Block
	var err error
	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}
	var gcm cipher.AEAD
	if gcm, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
