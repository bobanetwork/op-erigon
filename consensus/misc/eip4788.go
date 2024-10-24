package misc

import (
	"github.com/ledgerwatch/log/v3"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/params"
)

func ApplyBeaconRootEip4788(parentBeaconBlockRoot *libcommon.Hash, syscall consensus.SystemCall) {
	if parentBeaconBlockRoot == nil {
		log.Warn("Skipping EIP-4788 as there is no parentBeaconBlockRoot")
		return
	}
	_, err := syscall(params.BeaconRootsAddress, parentBeaconBlockRoot.Bytes())
	if err != nil {
		log.Warn("Failed to call beacon roots contract", "err", err)
	}
}
