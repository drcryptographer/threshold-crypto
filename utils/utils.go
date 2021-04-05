package utils

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"io"
	"math/big"
	"strconv"
	"strings"
)

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

func MarshalMessage(msg tss.Message) ([]byte, error) {
	buffer, _, _ := msg.WireBytes()
	message := struct {
		Index       int
		IsBroadcast bool

		Id      string
		Moniker string
		Wire    []byte
		Key     []byte
	}{
		Index:       msg.GetFrom().Index,
		Id:          msg.GetFrom().Id,
		Moniker:     msg.GetFrom().Moniker,
		IsBroadcast: msg.IsBroadcast(),
		Wire:        buffer,
		Key:         msg.GetFrom().Key,
	}
	return json.Marshal(&message)
}
func UnMarshalMessage(msg []byte) (tss.Message, error) {
	message := struct {
		Index       int
		IsBroadcast bool
		Wire        []byte
		Id          string
		Moniker     string
		Key         []byte
	}{}
	json.Unmarshal(msg, &message)
	from := tss.NewPartyID(message.Id, message.Moniker, new(big.Int).SetBytes(message.Key))
	from.Index = message.Index
	return tss.ParseWireMessage(message.Wire, from, message.IsBroadcast)
}
func UnMarshalMessageArray(msg [][]byte) ([]tss.Message, error) {
	var result = make([]tss.Message, len(msg))
	var err error
	for i := 0; i < len(result); i++ {
		if result[i], err = UnMarshalMessage(msg[i]); err != nil {
			return nil, err
		}
	}
	return result, nil
}
func MarshalMessageArray(msg []tss.Message) ([][]byte, error) {
	var result = make([][]byte, len(msg))
	var err error
	for i := 0; i < len(result); i++ {
		if result[i], err = MarshalMessage(msg[i]); err != nil {
			return nil, err
		}
	}
	return result, nil
}
