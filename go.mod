module github.com/clover-network/threshold-crypto

go 1.15

require (
	github.com/binance-chain/tss-lib v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd v0.21.0-beta // indirect
	github.com/btcsuite/btcutil v1.0.2
	github.com/ebfe/keccak v0.0.0-20150115210727-5cc570678d1b
	github.com/ethereum/go-ethereum v1.10.1
	github.com/fiatjaf/bip340 v1.0.0
	github.com/stretchr/testify v1.7.0
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
	golang.org/x/sys v0.0.0-20210314195730-07df6a141424 // indirect
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/genproto v0.0.0-20210315142602-88120395e650 // indirect
	google.golang.org/grpc v1.36.0
	google.golang.org/protobuf v1.25.0
)

replace github.com/binance-chain/tss-lib => github.com/clover-network/tss-lib v1.3.3-0.20210412152007-6f47151a1d8a
