// Portions copyright 2022-2023 mmontour@enya.ai based on legacy_tx.go (original copyright below)
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
	"github.com/ledgerwatch/erigon/rlp"
	"github.com/ledgerwatch/log/v3"
)

// DepositTransaction is the transaction data of an Optimism Deposit Transaction
type DepositTransaction struct {
	TransactionMisc

	SourceHash *libcommon.Hash
	From       *libcommon.Address
	To         *libcommon.Address
	Mint       *uint256.Int
	Value      *uint256.Int
	GasLimit   uint64
	IsSystemTx bool
	Data       []byte
}

func (tx DepositTransaction) GetBlobGas() uint64      { return 0 } // FIXME - do we need this?
func (tx DepositTransaction) GetGas() uint64          { return tx.GasLimit }
func (tx DepositTransaction) GetPrice() *uint256.Int  { return uint256.NewInt(0) }
func (tx DepositTransaction) GetTip() *uint256.Int    { return uint256.NewInt(0) }
func (tx DepositTransaction) GetFeeCap() *uint256.Int { return uint256.NewInt(0) }
func (tx DepositTransaction) GetNonce() uint64        { return 0 }
func (tx DepositTransaction) GetEffectiveGasTip(baseFee *uint256.Int) *uint256.Int {
	return uint256.NewInt(0)
}
func (tx *DepositTransaction) Unwrap() Transaction { return tx }

func (tx DepositTransaction) Cost() *uint256.Int {
	log.Error("Cost() called for a Deposit transaction")
	total := new(uint256.Int)
	return total
}

func (tx DepositTransaction) GetAccessList() types2.AccessList {
	return types2.AccessList{}
}
func (tx DepositTransaction) GetData() []byte {
	return tx.Data
}
func (tx DepositTransaction) GetBlobHashes() []libcommon.Hash {
	// Only blob txs have data hashes
	return []libcommon.Hash{}
}

func (tx DepositTransaction) Protected() bool {
	return true
}

func (tx DepositTransaction) EncodingSize() int {
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
func (tx DepositTransaction) copy() *DepositTransaction {
	cpy := &DepositTransaction{
		SourceHash: tx.SourceHash,
		From:       tx.From,
		To:         tx.To,
		Mint:       tx.Mint,
		Value:      tx.Value,
		GasLimit:   tx.GasLimit,
		IsSystemTx: tx.IsSystemTx,
		Data:       libcommon.CopyBytes(tx.Data),
	}

	return cpy
}

// MarshalBinary returns the canonical encoding of the transaction.
func (tx DepositTransaction) MarshalBinary(w io.Writer) error {
	return tx.EncodeRLP(w)
}

// EncodeRLP implements rlp.Encoder
func (tx DepositTransaction) EncodeRLP(w io.Writer) error {
	var b [33]byte
	rlp.EncodeInt(DepositTxType, w, b[:])

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
	if err := tx.Mint.EncodeRLP(w); err != nil {
		return err
	}
	if err := tx.Value.EncodeRLP(w); err != nil {
		return err
	}
	if err := rlp.EncodeInt(tx.GasLimit, w, b[:]); err != nil {
		return err
	}
	boolVal := uint64(0)
	if tx.IsSystemTx {
		boolVal = 1
	}
	if err := rlp.EncodeInt(boolVal, w, b[:]); err != nil {
		return err
	}
	if err := rlp.EncodeString(tx.Data, w, b[:]); err != nil {
		return err
	}

	return nil
}

func (tx DepositTransaction) payloadSize() int {
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

	// Mint
	payloadSize++
	payloadSize += rlp.Uint256LenExcludingHead(tx.Mint)

	// Value
	payloadSize++
	payloadSize += rlp.Uint256LenExcludingHead(tx.Value)

	// GasLimit
	payloadSize++
	payloadSize += rlp.IntLenExcludingHead(tx.GasLimit)

	// IsSystemTx
	payloadSize++

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

// DecodeRLP decodes DepositTransaction but with the list token already consumed and encodingSize being presented
func (tx *DepositTransaction) DecodeRLP(s *rlp.Stream) error {
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

	if b, err = s.Uint256Bytes(); err != nil {
		return fmt.Errorf("read Mint: %w", err)
	}
	tx.Mint = new(uint256.Int).SetBytes(b)

	if b, err = s.Uint256Bytes(); err != nil {
		return fmt.Errorf("read Value: %w", err)
	}
	tx.Value = new(uint256.Int).SetBytes(b)

	if tx.GasLimit, err = s.Uint(); err != nil {
		return fmt.Errorf("read GasLimit: %w", err)
	}

	if tx.IsSystemTx, err = s.Bool(); err != nil {
		return fmt.Errorf("read IsSystemTx: %w", err)
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
func (tx DepositTransaction) AsMessage(s Signer, _ *big.Int, rules *chain.Rules) (Message, error) {
	msg := Message{
		txType:        DepositTxType,
		sourceHash:    tx.SourceHash,
		from:          *tx.From,
		gasLimit:      tx.GasLimit,
		to:            tx.To,
		mint:          *tx.Mint,
		amount:        *tx.Value,
		isSystemTx:    tx.IsSystemTx,
		data:          tx.Data,
		accessList:    nil,
		checkNonce:    true,
		rollupDataGas: RollupDataGas(tx, rules),
	}
	return msg, nil
}

func (tx *DepositTransaction) WithSignature(signer Signer, sig []byte) (Transaction, error) {
	log.Error("WithSignature() called for a Deposit transaction")
	cpy := tx.copy()
	return cpy, nil
}

func (tx *DepositTransaction) FakeSign(address libcommon.Address) (Transaction, error) {
	log.Error("FakeSign() called for a Deposit transaction")
	cpy := tx.copy()
	return cpy, nil
}

// Hash computes the hash (but not for signatures!)
func (tx *DepositTransaction) Hash() libcommon.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return *hash.(*libcommon.Hash)
	}
	hash := prefixedRlpHash(
		DepositTxType,
		[]interface{}{
			tx.SourceHash,
			tx.From,
			tx.To,
			tx.Mint,
			tx.Value,
			tx.GasLimit,
			tx.IsSystemTx,
			tx.Data,
		},
	)
	tx.hash.Store(&hash)
	return hash

}

func (tx DepositTransaction) SigningHash(chainID *big.Int) libcommon.Hash {
	log.Error("SigningHash() called for a Deposit transaction")
	return libcommon.Hash{}
}

func (tx DepositTransaction) Type() byte { return DepositTxType }

func (tx DepositTransaction) RawSignatureValues() (*uint256.Int, *uint256.Int, *uint256.Int) {
	log.Error("SigningHash() called for a Deposit transaction")
	return uint256.NewInt(0), uint256.NewInt(0), uint256.NewInt(0)
}

func (tx DepositTransaction) GetChainID() *uint256.Int {
	log.Error("GetChainID() called for a Deposit transaction")
	return new(uint256.Int)
}
func (tx DepositTransaction) GetSender() (libcommon.Address, bool) {
	return *tx.From, true
}
func (tx DepositTransaction) GetTo() *libcommon.Address {
	return tx.To
}

func (tx DepositTransaction) GetValue() *uint256.Int {
	return tx.Value
}

func (tx DepositTransaction) IsContractDeploy() bool {
	return tx.GetTo() == nil
}

func (tx DepositTransaction) IsDepositTx() bool {
	return true
}

func (tx DepositTransaction) IsStarkNet() bool {
	return false
}

func (tx *DepositTransaction) Sender(signer Signer) (libcommon.Address, error) {
	return *tx.From, nil
}
func (tx *DepositTransaction) SetSender(addr libcommon.Address) {
	if tx.From != nil && *tx.From != addr {
		log.Error("SetSender() address confict for Deposit transaction", "old", tx.From, "new", addr)
	}
	// otherwise a NOP
}
