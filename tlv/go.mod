module github.com/lightningnetwork/lnd/tlv

require (
	github.com/btcsuite/btcd v0.23.5-0.20230905170901-80f5a0ffdf36
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/lightningnetwork/lnd/fn v1.0.0
	github.com/stretchr/testify v1.8.2
	golang.org/x/exp v0.0.0-20231127185646-65229373498e
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.2 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	golang.org/x/crypto v0.16.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/lightningnetwork/lnd/fn => ../fn

go 1.19
