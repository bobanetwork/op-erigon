// (insert license+copyright statement)

package vm

import (
//	"sync/atomic"
	"math/big"
	"golang.org/x/crypto/sha3"

//	"github.com/holiman/uint256"

//	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"

//	"github.com/ledgerwatch/erigon/common/u256"
//	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
//	"github.com/ledgerwatch/erigon/crypto"
//	"github.com/ledgerwatch/erigon/params"
	"github.com/ledgerwatch/log/v3"
)

// Hybrid Compute extension
type HCContext struct {
	HcFlag   int
	ReqHash  *libcommon.Hash
	Request  []byte
	Response []byte
	MayBlock bool
	Failed bool
}

var HCResponseCache map[libcommon.Hash] *HCContext

func HCKey (addr libcommon.Address, nonce uint64, data []byte) libcommon.Hash {
	var bNonce big.Int
	bNonce.SetUint64(nonce)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(addr.Bytes())
	// hasher.Write(bNonce.Bytes()) // FIXME
	hasher.Write(data)
	key := libcommon.BytesToHash(hasher.Sum(nil))
	log.Debug("MMDBG-HC HCKey", "key", key, "addr", addr, "nonce", nonce, "data", data)
	
	return key
}
