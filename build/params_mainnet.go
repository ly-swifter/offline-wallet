//go:build !debug && !2k && !testground && !calibnet && !butterflynet && !interopnet
// +build !debug,!2k,!testground,!calibnet,!butterflynet,!interopnet

package build

import "github.com/filecoin-project/go-address"

const NetworkName = "main"

func init() {
	SetAddressNetwork(address.Mainnet)
}
