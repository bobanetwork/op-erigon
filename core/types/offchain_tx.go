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
	"bytes"
	"fmt"
	"io"
	"math/big"

	rlp2 "github.com/ethereum/go-ethereum/rlp" // Use this one to avoid a bunch of BS with the ledgerwatch/erigon/rlp version
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

func (tx OffchainTransaction) GetDataGas() uint64      { return 0 } // FIXME - do we need this?
func (tx OffchainTransaction) GetGas() uint64          { return tx.GasLimit }
func (tx OffchainTransaction) GetPrice() *uint256.Int  { return uint256.NewInt(0) }
func (tx OffchainTransaction) GetTip() *uint256.Int    { return uint256.NewInt(0) }
func (tx OffchainTransaction) GetFeeCap() *uint256.Int { return uint256.NewInt(0) }
func (tx OffchainTransaction) GetNonce() uint64        { return 0 }
func (tx OffchainTransaction) GetEffectiveGasTip(baseFee *uint256.Int) *uint256.Int {
	/*
		if baseFee == nil {
			return tx.GetTip()
		}
		gasFeeCap := tx.GetFeeCap()
		// return 0 because effectiveFee cant be < 0
		if gasFeeCap.Lt(baseFee) {
			return uint256.NewInt(0)
		}
		effectiveFee := new(uint256.Int).Sub(gasFeeCap, baseFee)
		if tx.GetTip().Lt(effectiveFee) {
			return tx.GetTip()
		} else {
			return effectiveFee
		}
	*/
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
func (tx OffchainTransaction) GetDataHashes() []libcommon.Hash {
	// Only blob txs have data hashes
	return []libcommon.Hash{}
}

func (tx OffchainTransaction) Protected() bool {
	return true
}

func (tx OffchainTransaction) EncodingSize() int {
	// FIXME - inefficient
	var bb bytes.Buffer
	tx.EncodeRLP(&bb)
	log.Debug("Offchain tx EncodingSize", "tx", tx, "len", bb.Len())

	return bb.Len()
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

	var bb bytes.Buffer
	buf := rlp2.NewEncoderBuffer(&bb)
	buf.WriteUint64(uint64(OffchainTxType))
	idx1 := buf.List()
	buf.WriteBytes(tx.SourceHash.Bytes())
	buf.WriteBytes(tx.From.Bytes())
	buf.WriteBytes(tx.To.Bytes())
	buf.WriteUint64(tx.GasLimit)
	buf.WriteBytes(tx.Data)
	buf.ListEnd(idx1)

	w.Write(buf.ToBytes())

	return nil
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
	if len(b) != 20 {
		return fmt.Errorf("wrong size for To: %d", len(b))
	}
	tx.To = &libcommon.Address{}
	copy((*tx.To)[:], b)

	if tx.GasLimit, err = s.Uint(); err != nil {
		return fmt.Errorf("read GasLimit: %w", err)
	}

	if tx.Data, err = s.Bytes(); err != nil {
		return fmt.Errorf("read Data: %w", err)
	}

	if err = s.ListEnd(); err != nil {
		return fmt.Errorf("close tx struct: %w", err)
	}

	log.Debug("Offchain DecodeRLP successful", "tx", tx)
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
	hcHelper := libcommon.HexToAddress("0x42000000000000000000000000000000000000Fd")

	ret := &OffchainTransaction{
		SourceHash: &hcHash,
		From:       &hcFrom,
		To:         &hcHelper,
		GasLimit:   gasLimit,
		Data:       common.CopyBytes(data),
	}

	return ret
}
