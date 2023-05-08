package state

import (
	"errors"

	"github.com/ledgerwatch/erigon-lib/common"
)

var (
	errInvalidType   = errors.New("invalid type")
	errUnimplemented = errors.New("type unimplemented")
)

// StorageValues represents the values to be set in storage.
// The key is the name of the storage variable and the value
// is the value to set in storage.
type StorageValues map[string]any

// StorageConfig represents the storage configuration for the L2 predeploy
// contracts.
type StorageConfig map[string]StorageValues

// EncodedStorage represents the storage key and value serialized
// to be placed in Ethereum state.
type EncodedStorage struct {
	Key   common.Hash
	Value common.Hash
}
