package utils

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/ebfe/keccak"
	"math/big"
)

func IntToBytes(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}

func ToPoint(curve elliptic.Curve, x []byte) (*big.Int, *big.Int, error) {
	if len(x) != 32 {
		panic("Bad x len")
	}
	return LiftX(curve, new(big.Int).SetBytes(x))
}

func LiftX(curve elliptic.Curve, x *big.Int) (*big.Int, *big.Int, error) {
	P := curve.Params().P
	if x.Cmp(big.NewInt(0)) == -1 || x.Cmp(P) == 1 {
		return nil, nil, errors.New("Bad x")
	}
	c := new(big.Int)
	c.Exp(x, big.NewInt(3), P)
	c.Add(c, big.NewInt(7))
	c.Mod(c, P)
	exp := new(big.Int)
	exp.Add(P, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	y := new(big.Int)
	y.Exp(c, exp, P)
	ysquared := new(big.Int)
	ysquared.Exp(y, big.NewInt(2), P)
	if c.Cmp(ysquared) != 0 {
		return nil, nil, errors.New("Bad c")
	}
	return x, y, nil
}
func LiftXEvenY(curve elliptic.Curve, x *big.Int) (*big.Int, *big.Int, error) {
	Px, Py, err := LiftX(curve, x)
	if err != nil {
		return nil, nil, err
	}
	if IsEven(Py) {
		return Px, Py, nil
	} else {
		Py.Sub(curve.Params().P, Py)
		return Px, Py, nil
	}
}

func IsEven(b *big.Int) bool {
	return b.Bit(0) == 0
}

//bitcoin schnorr
func GetBip340E(Px, Py *big.Int, rX []byte, m [32]byte) *big.Int {
	bundle := bytes.Buffer{}
	bundle.Write(rX)
	bundle.Write(IntToBytes(Px))
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

func GetScalarETH(message []byte, Rx, Ry, Px, Py *big.Int) *big.Int {
	keccakHash := keccak.New256()
	keccakHash.Write(IntToBytes(Rx))
	keccakHash.Write(IntToBytes(Ry))
	keccakHash.Write(IntToBytes(Px))
	keccakHash.Write(IntToBytes(Py))
	keccakHash.Write(message[:])

	result := big.NewInt(0).SetBytes(keccakHash.Sum(nil))
	return new(big.Int).Mod(
		result,
		tss.EC().Params().N,
	)
}
