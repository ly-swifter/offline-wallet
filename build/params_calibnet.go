//go:build calibnet
// +build calibnet

package build

import "github.com/filecoin-project/go-address"

const NetworkName = "test"

func init() {
	SetAddressNetwork(address.Testnet)
}
