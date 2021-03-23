package utils

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/ebfe/keccak"
	"io"
	"math/big"
	"strconv"
	"strings"
)

//bitcoin schnorr
func GetBip340E(Px, Py *big.Int, rX []byte, m [32]byte) *big.Int {
	bundle := bytes.Buffer{}
	bundle.Write(rX)
	bundle.Write(Px.Bytes())
	bundle.Write(m[:])
	return new(big.Int).Mod(
		new(big.Int).SetBytes(HashWithTag("BIP0340/challenge", bundle.Bytes())),
		tss.EC().Params().N,
	)
}
func HashWithTag(tag string, msg []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(msg)
	return h.Sum(nil)
}

//ethereum schnorr
func GetScalar2(message [32]byte, r []byte, PublicKey *crypto.ECPoint) *big.Int {
	keccakHash := keccak.New256()

	keccakHash.Write(r)
	compressedPubKey := elliptic.MarshalCompressed(tss.EC(), PublicKey.X(), PublicKey.Y())
	keccakHash.Write(compressedPubKey)
	keccakHash.Write(message[:])

	result := big.NewInt(0).SetBytes(keccakHash.Sum(nil))
	return result
}

func ScalarECCBaseMult(curve elliptic.Curve, k *big.Int) *Point {
	x, y := curve.ScalarBaseMult(k.Bytes())
	if k.Sign() == -1 {
		y.Sub(curve.Params().P, y)
	}
	return &Point{
		X: x,
		Y: y,
	}
}
func GetId(certificate *x509.Certificate) int32 {
	return GetIdofCert(certificate.Subject.CommonName)
}
func GetIdofCert(name string) int32 {
	var id = strings.TrimPrefix(name, "agent=")
	if id == name {
		return -1
	}
	var result, err = strconv.Atoi(id)
	if err != nil {
		return -1
	}
	return int32(result)
}

func ScalarECCMult(curve elliptic.Curve, point *Point, k *big.Int) *Point {
	rx, ry := curve.ScalarMult(point.X, point.Y, k.Bytes())
	if k.Sign() == -1 {
		ry.Sub(curve.Params().P, ry)
	}
	return &Point{
		X: rx,
		Y: ry,
	}
}
func ComputeHash256(nums ...*big.Int) *big.Int {
	hash := sha256.New()
	for _, nxt := range nums {
		hash.Write(nxt.Bytes())
	}
	return new(big.Int).SetBytes(hash.Sum([]byte{}))
}

var ZERO = big.NewInt(0)
var ONE = big.NewInt(1)

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomInZnStar(n *big.Int, random io.Reader) (*big.Int, error) {
	r, err := rand.Int(random, n)
	if err != nil {
		return nil, err
	}
	if ZERO.Cmp(r) == 0 || ONE.Cmp(new(big.Int).GCD(nil, nil, n, r)) != 0 {
		return GetRandomInZnStar(n, random)
	}
	return r, nil
}

type Point struct {
	X, Y *big.Int
}

func (p *Point) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		X string `json:"X"`
		Y string `json:"Y"`
	}{
		X: strings.ToUpper(hex.EncodeToString(p.X.Bytes())),
		Y: strings.ToUpper(hex.EncodeToString(p.Y.Bytes())),
	})
}
func (p *Point) UnmarshalJSON(data []byte) error {
	aux := struct {
		X string `json:"X"`
		Y string `json:"Y"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	buffer, _ := hex.DecodeString(aux.X)
	p.X = new(big.Int).SetBytes(buffer)

	buffer, _ = hex.DecodeString(aux.Y)
	p.Y = new(big.Int).SetBytes(buffer)
	return nil
}

func ParsePoly(buffer []byte) (vss.Vs, error) {
	result := vss.Vs{}
	err := json.Unmarshal(buffer, &result)
	return result, err
}
func ParseShare(buffer []byte) (*vss.Share, error) {
	result := &vss.Share{}
	err := json.Unmarshal(buffer, &result)
	return result, err
}

func ToBytes(data interface{}) []byte {
	buffer, _ := json.Marshal(&data)
	return buffer
}
func ReConstructSecret(shares ...*vss.Share) (*big.Int, error) {
	sharesFinal := make(vss.Shares, len(shares))
	for i, next := range shares {
		sharesFinal[i] = next
	}
	return sharesFinal.ReConstruct()
}
