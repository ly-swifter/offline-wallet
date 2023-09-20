package build

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/filecoin-project/lotus/node/modules/dtypes"
)

var BlockExplorer map[dtypes.NetworkName]string

var FilForwarderAddress = common.HexToAddress("0x2B3ef6906429b580b7b2080de5CA893BC282c225")

func init() {
	if BlockExplorer == nil {
		BlockExplorer = make(map[dtypes.NetworkName]string)
	}
	BlockExplorer["mainnet"] = `https://filfox.info/message/%s`
	BlockExplorer["calibrationnet"] = `https://calibration.filfox.info/message/%s`
	BlockExplorer["hyperspace"] = `https://hyperspace.filfox.info/message/%s`
}
