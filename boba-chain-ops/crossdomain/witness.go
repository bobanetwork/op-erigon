package crossdomain

import "github.com/ledgerwatch/erigon-lib/common"

// Allowance represents the allowances that were set in the
// legacy ERC20 representation of ether
type Allowance struct {
	From common.Address `json:"fr"`
	To   common.Address `json:"to"`
}
