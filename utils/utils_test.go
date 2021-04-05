package utils

import (
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
	"testing"
)

func TestMarshalMessage(t *testing.T) {
	ids := []int{1, 5, 4}
	pIDs := GetSortedPartyID(ids)
	var pi paillier.Proof

	var messages []tss.Message
	messages = append(messages, keygen.NewKGRound3Message(pIDs[0], pi))
	messages = append(messages, keygen.NewKGRound3Message(pIDs[1], pi))

	buffer, _ := MarshalMessageArray(messages)

	message2, _ := UnMarshalMessageArray(buffer)
	println(message2[0].GetFrom().Id)
	println(message2[1].GetFrom().Id)

}
