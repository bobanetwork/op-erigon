// Copyright 2022-2023 mmontour@enya.ai based on legacy_tx.go (original copyright below)
// This file adds support for the Optimistic Rollup deposit transaction type
// as specified at https://github.com/ethereum-optimism/optimism/blob/develop/specs/deposits.md

// Copyright 2020 The go-ethereum Authors
//
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//

package types

import (
	"fmt"
	"io"
	"math/big"
	"math/bits"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	types2 "github.com/ledgerwatch/erigon-lib/types"
	"github.com/ledgerwatch/erigon/common"
	"github.com/ledgerwatch/erigon/rlp"
	"github.com/ledgerwatch/log/v3"
)

// OffchainTransaction is inserted by the Sequencer ahead of a user-submitted Hybrid Compute tx
type OffchainTransaction struct {
	TransactionMisc

	SourceHash *libcommon.Hash
	From       *libcommon.Address
	To         *libcommon.Address
	GasLimit   uint64
	Data       []byte
}

// Address of the HCHelper contract
const HC_PREDEPLOY = "0x42000000000000000000000000000000000003E9"

func (tx OffchainTransaction) GetBlobGas() uint64      { return 0 }
func (tx OffchainTransaction) GetGas() uint64          { return tx.GasLimit }
func (tx OffchainTransaction) GetPrice() *uint256.Int  { return uint256.NewInt(0) }
func (tx OffchainTransaction) GetTip() *uint256.Int    { return uint256.NewInt(0) }
func (tx OffchainTransaction) GetFeeCap() *uint256.Int { return uint256.NewInt(0) }
func (tx OffchainTransaction) GetNonce() uint64        { return 0 }
func (tx OffchainTransaction) GetEffectiveGasTip(baseFee *uint256.Int) *uint256.Int {
	return uint256.NewInt(0)
}
func (tx *OffchainTransaction) Unwrap() Transaction { return tx }

func (tx OffchainTransaction) Cost() *uint256.Int {
	log.Warn("Cost() called for Offchain tx")
	total := new(uint256.Int).SetUint64(0)
	return total
}

func (tx OffchainTransaction) GetAccessList() types2.AccessList {
	return types2.AccessList{}
}
func (tx OffchainTransaction) GetData() []byte {
	return tx.Data
}
func (tx OffchainTransaction) GetBlobHashes() []libcommon.Hash {
	// Only blob txs have data hashes
	return []libcommon.Hash{}
}

func (tx OffchainTransaction) Protected() bool {
	return true
}

func (tx OffchainTransaction) EncodingSize() int {
	payloadSize := tx.payloadSize()
	envelopeSize := payloadSize
	// Add envelope size and type size
	if payloadSize >= 56 {
		envelopeSize += libcommon.BitLenToByteLen(bits.Len(uint(payloadSize)))
	}
	envelopeSize += 2
	return envelopeSize
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx OffchainTransaction) copy() *OffchainTransaction {
	cpy := &OffchainTransaction{
		SourceHash: tx.SourceHash,
		From:       tx.From,
		To:         tx.To,
		GasLimit:   tx.GasLimit,
		Data:       common.CopyBytes(tx.Data),
	}

	return cpy
}

// MarshalBinary returns the canonical encoding of the transaction.
// For legacy transactions, it returns the RLP encoding. For EIP-2718 typed
// transactions, it returns the type and payload.
func (tx OffchainTransaction) MarshalBinary(w io.Writer) error {
	return tx.EncodeRLP(w)
}

// EncodeRLP implements rlp.Encoder
func (tx OffchainTransaction) EncodeRLP(w io.Writer) error {
	var b [33]byte
	rlp.EncodeInt(OffchainTxType, w, b[:])

	payloadSize := tx.payloadSize()

	// prefix
	if err := EncodeStructSizePrefix(payloadSize, w, b[:]); err != nil {
		return err
	}
	if err := rlp.EncodeString(tx.SourceHash[:], w, b[:]); err != nil {
		return err
	}
	if err := rlp.EncodeString(tx.From[:], w, b[:]); err != nil {
		return err
	}
	if tx.To == nil {
		b[0] = 128
	} else {
		b[0] = 128 + 20
	}
	if _, err := w.Write(b[:1]); err != nil {
		return err
	}
	if tx.To != nil {
		if _, err := w.Write(tx.To.Bytes()); err != nil {
			return err
		}
	}
	/*	if err := tx.Value.EncodeRLP(w); err != nil {
			return err
		}
	*/
	if err := rlp.EncodeInt(tx.GasLimit, w, b[:]); err != nil {
		return err
	}
	if err := rlp.EncodeString(tx.Data, w, b[:]); err != nil {
		return err
	}

	return nil
}

func (tx OffchainTransaction) payloadSize() int {
	// SourceHash
	payloadSize := 1
	payloadSize += len(tx.SourceHash)

	// From
	payloadSize++
	payloadSize += len(tx.From)

	// To
	payloadSize++
	if tx.To != nil {
		payloadSize += len(tx.To)
	}

	/*	// Value
		payloadSize++
		payloadSize += rlp.Uint256LenExcludingHead(tx.Value)
	*/
	// GasLimit
	payloadSize++
	payloadSize += rlp.IntLenExcludingHead(tx.GasLimit)
	// size of Data
	payloadSize++
	switch len(tx.Data) {
	case 0:
	case 1:
		if tx.Data[0] >= 128 {
			payloadSize++
		}
	default:
		if len(tx.Data) >= 56 {
			payloadSize += libcommon.BitLenToByteLen(bits.Len(uint(len(tx.Data))))
		}
		payloadSize += len(tx.Data)
	}
	return payloadSize
}

// DecodeRLP decodes OffchainTransaction but with the list token already consumed and encodingSize being presented
func (tx *OffchainTransaction) DecodeRLP(s *rlp.Stream) error {
	var err error
	var b []byte

	if _, err := s.List(); err != nil {
		return fmt.Errorf("list header: %w", err)
	}

	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read SourceHash: %w", err)
	}
	tx.SourceHash = new(libcommon.Hash)
	tx.SourceHash.SetBytes(b)

	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read From: %w", err)
	}
	if len(b) != 20 {
		return fmt.Errorf("wrong size for From: %d", len(b))
	}
	tx.From = &libcommon.Address{}
	copy((*tx.From)[:], b)

	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read To: %w", err)
	}
	switch len(b) {
	case 20:
		tx.To = &libcommon.Address{}
		copy((*tx.To)[:], b)
	case 0:
		// contract creation
	default:
		return fmt.Errorf("wrong size for To: %d", len(b))
	}
	/*
		if b, err = s.Uint256Bytes(); err != nil {
			return fmt.Errorf("read Value: %w", err)
		}
		tx.Value = new(uint256.Int).SetBytes(b)
	*/
	if tx.GasLimit, err = s.Uint(); err != nil {
		return fmt.Errorf("read GasLimit: %w", err)
	}
	if tx.Data, err = s.Bytes(); err != nil {
		return fmt.Errorf("read Data: %w", err)
	}

	if err = s.ListEnd(); err != nil {
		return fmt.Errorf("close tx struct: %w", err)
	}

	return nil
}

// AsMessage returns the transaction as a core.Message.
func (tx OffchainTransaction) AsMessage(_ Signer, _ *big.Int, rules *chain.Rules) (Message, error) {
	msg := Message{
		txType:        OffchainTxType,
		sourceHash:    tx.SourceHash,
		from:          *tx.From,
		gasLimit:      tx.GasLimit,
		to:            tx.To,
		data:          tx.Data,
		accessList:    nil,
		checkNonce:    true,
		rollupDataGas: RollupDataGas(tx, rules),
	}
	return msg, nil
}

func (tx *OffchainTransaction) WithSignature(signer Signer, sig []byte) (Transaction, error) {
	log.Error("WithSignature() called for an Offchain transaction")
	cpy := tx.copy()
	return cpy, nil
}

func (tx *OffchainTransaction) FakeSign(address libcommon.Address) (Transaction, error) {
	log.Error("FakeSign() called for an Offchain transaction")
	cpy := tx.copy()
	return cpy, nil
}

// Hash computes the hash (but not for signatures!)
func (tx *OffchainTransaction) Hash() libcommon.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return *hash.(*libcommon.Hash)
	}
	hash := rlpHash([]interface{}{
		tx.SourceHash,
		tx.From,
		tx.To,
		tx.GasLimit,
		tx.Data,
	})
	tx.hash.Store(&hash)
	return hash

}

func (tx OffchainTransaction) SigningHash(chainID *big.Int) libcommon.Hash {
	log.Error("SigningHash() called for an Offchain transaction")
	return libcommon.Hash{}
}

func (tx OffchainTransaction) Type() byte { return OffchainTxType }

func (tx OffchainTransaction) RawSignatureValues() (*uint256.Int, *uint256.Int, *uint256.Int) {
	log.Error("RawSignatureValues() called for an Offchain transaction")
	return uint256.NewInt(0), uint256.NewInt(0), uint256.NewInt(0)
}

func (tx OffchainTransaction) GetChainID() *uint256.Int {
	log.Error("GetChainID() called for an Offchain transaction")
	return new(uint256.Int)
}
func (tx OffchainTransaction) GetSender() (libcommon.Address, bool) {
	return *tx.From, true
}
func (tx OffchainTransaction) GetTo() *libcommon.Address {
	return tx.To
}

func (tx OffchainTransaction) GetValue() *uint256.Int {
	return new(uint256.Int)
}

func (tx OffchainTransaction) IsContractDeploy() bool {
	return false
}

func (tx OffchainTransaction) IsDepositTx() bool {
	return false
}

func (tx OffchainTransaction) IsStarkNet() bool {
	return false
}

func (tx *OffchainTransaction) Sender(signer Signer) (libcommon.Address, error) {
	return *tx.From, nil
}
func (tx *OffchainTransaction) SetSender(addr libcommon.Address) {
	if tx.From != nil && *tx.From != addr {
		log.Error("SetSender() address confict for Offchain transaction", "old", tx.From, "new", addr)
	}
	// otherwise a NOP
}

func NewOffchainTx(hcHash libcommon.Hash, data []byte, gasLimit uint64) *OffchainTransaction {
	hcFrom := libcommon.HexToAddress("0xdEAddEadDeaDDEaDDeadDeAddeadDEaddeaD9901")
	hcHelper := libcommon.HexToAddress(HC_PREDEPLOY)

	ret := &OffchainTransaction{
		SourceHash: &hcHash,
		From:       &hcFrom,
		To:         &hcHelper,
		GasLimit:   gasLimit,
		Data:       common.CopyBytes(data),
	}

	return ret
}
