// Copyright 2022 mmontour@enya.ai based on legacy_tx.go (original copyright below)
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
	//"encoding/binary"
	"fmt"
	"io"
	"math/big"
	//"math/bits"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon/common"
	//"github.com/ledgerwatch/erigon/common/u256"
	"github.com/ledgerwatch/erigon/params"
	"github.com/ledgerwatch/erigon/rlp"
	"github.com/ledgerwatch/log/v3"
	"bytes"
	rlp2 "github.com/ethereum/go-ethereum/rlp"	// Use this one to avoid a bunch of BS with the ledgerwatch/erigon/rlp version

)


// DepositTransaction is the transaction data of regular Ethereum transactions.
type DepositTransaction struct {
	TransactionMisc
	
	SourceHash *common.Hash
	Nonce      uint64
	From       *common.Address
	To         *common.Address
	Mint       *uint256.Int
	Value      *uint256.Int
	GasLimit   uint64
	IsSystemTx bool
	Data	   []byte
}


func (tx DepositTransaction) GetGas() uint64 { return tx.GasLimit }
func (tx DepositTransaction) GetPrice() *uint256.Int { return uint256.NewInt(0) }
func (tx DepositTransaction) GetTip() *uint256.Int { return uint256.NewInt(0) }
func (tx DepositTransaction) GetFeeCap() *uint256.Int { return uint256.NewInt(0) }
func (tx DepositTransaction) GetNonce() uint64 { return tx.Nonce }
func (tx DepositTransaction) GetEffectiveGasTip(baseFee *uint256.Int) *uint256.Int {
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


func (tx DepositTransaction) Cost() *uint256.Int {
	log.Warn("MMDBG dtX Cost")
	total := new(uint256.Int).SetUint64(0) // FIXME
	//total.Mul(total, tx.GasPrice)
	//total.Add(total, tx.Value)
	return total
}

func (tx DepositTransaction) GetAccessList() AccessList {
	return AccessList{}
}
func (tx DepositTransaction) GetData() []byte {
	return tx.Data
}

func (tx DepositTransaction) Protected() bool {
	return true	// FIXME
}


// copy creates a deep copy of the transaction data and initializes all fields.
func (tx DepositTransaction) copy() *DepositTransaction {
	cpy := &DepositTransaction{
		SourceHash: tx.SourceHash,
		Nonce: tx.Nonce,
		From: tx.From,
		To: tx.To,
		Mint: tx.Mint,
		Value: tx.Value,
		GasLimit: tx.GasLimit,
		IsSystemTx: tx.IsSystemTx,
		Data: common.CopyBytes(tx.Data),
	}


	return cpy
}


func (tx *DepositTransaction) Size() common.StorageSize {
	log.Warn("MMDBG dtX Size")
	if size := tx.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := 42 // FIXME
	tx.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}


// MarshalBinary returns the canonical encoding of the transaction.
// For legacy transactions, it returns the RLP encoding. For EIP-2718 typed
// transactions, it returns the type and payload.
func (tx DepositTransaction) MarshalBinary(w io.Writer) error {
	//log.Debug("MMDBG MarshalBinary calling EncodeRLP")
	return tx.EncodeRLP(w)
}


// EncodeRLP implements rlp.Encoder
func (tx DepositTransaction) EncodeRLP(w io.Writer) error {
	
	var bb bytes.Buffer
	buf := rlp2.NewEncoderBuffer(&bb)
	buf.WriteUint64(DepositTxType)
	idx1 := buf.List()
	buf.WriteBytes(tx.SourceHash.Bytes())
	buf.WriteBytes(tx.From.Bytes())
	buf.WriteBytes(tx.To.Bytes())
	buf.WriteBytes(tx.Mint.Bytes())
	buf.WriteBytes(tx.Value.Bytes())
	buf.WriteUint64(tx.GasLimit)
	buf.WriteBool(tx.IsSystemTx)
	buf.WriteBytes(tx.Data)
	buf.ListEnd(idx1)
	
	//log.Debug("MMDBG EncodeRLP", "bufBytes", buf.ToBytes())
	w.Write(buf.ToBytes())
	
	return nil
}

// DecodeRLP decodes DepositTransaction but with the list token already consumed and encodingSize being presented
func (tx *DepositTransaction) DecodeRLP(s *rlp.Stream) error {
	var err error
	var b []byte
		
	if _, err := s.List(); err != nil {
		return fmt.Errorf("list header: %w", err)
	}
	
	tx.Nonce = 0xffff_ffff_ffff_fffd  // DepositsNonce from Optimism
	
	
	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read SourceHash: %w", err)
	}
	tx.SourceHash = new(common.Hash)
	tx.SourceHash.SetBytes(b)

	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read From: %w", err)
	}
	if len(b) != 20 {
		return fmt.Errorf("wrong size for From: %d", len(b))
	}
	tx.From = &common.Address{}
	copy((*tx.From)[:], b)

	if b, err = s.Bytes(); err != nil {
		return fmt.Errorf("read To: %w", err)
	}
	if len(b) != 20 {
		return fmt.Errorf("wrong size for To: %d", len(b))
	}
	tx.To = &common.Address{}
	copy((*tx.To)[:], b)

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
	
	log.Debug("MMDBG DecodeRLP successful", "tx", tx)
	return nil
}

// AsMessage returns the transaction as a core.Message.
func (tx DepositTransaction) AsMessage(s Signer, _ *big.Int, _ *params.Rules) (Message, error) {
	//log.Warn("MMDBG dtX AsMessage")
	msg := Message{
		sourceHash: tx.SourceHash,
		nonce:      tx.Nonce,
		from:       *tx.From,
		gasLimit:   tx.GasLimit,
		to:         tx.To,
		mint:       *tx.Mint,
		amount:     *tx.Value,
		isSystemTx: tx.IsSystemTx,
		data:       tx.Data,
		accessList: nil,
		checkNonce: true,
	}

	var err error
	//msg.from, err = tx.Sender(s)
	log.Debug("MMDBG dtX AsMessage", "msg", msg)
	return msg, err
}

func (tx *DepositTransaction) WithSignature(signer Signer, sig []byte) (Transaction, error) {
	log.Warn("MMDBG dtX WithSignature")
	cpy := tx.copy()
	/*
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy.R.Set(r)
	cpy.S.Set(s)
	cpy.V.Set(v)
	*/
	return cpy, nil
}

func (tx *DepositTransaction) FakeSign(address common.Address) (Transaction, error) {
	log.Warn("MMDBG dtX FakeSign")
	cpy := tx.copy()
//	cpy.R.Set(u256.Num1)
//	cpy.S.Set(u256.Num1)
//	cpy.V.Set(u256.Num4)
//	cpy.from.Store(address)
	return cpy, nil
}


// Hash computes the hash (but not for signatures!)
func (tx *DepositTransaction) Hash() common.Hash {
	//log.Warn("MMDBG dtX Hash")

	if hash := tx.hash.Load(); hash != nil {
		return *hash.(*common.Hash)
	}
	hash := rlpHash([]interface{}{
		tx.SourceHash,
		tx.From,
		tx.To,
		tx.Mint,
		tx.Value,
		tx.GasLimit,
		tx.IsSystemTx,
		tx.Data,
	})
	tx.hash.Store(&hash)
	return hash

}

func (tx DepositTransaction) SigningHash(chainID *big.Int) common.Hash {
	return common.Hash{} // FIXME
}

/*
func (tx DepositTransaction) SigningHash(chainID *big.Int) common.Hash {
	if chainID != nil && chainID.Sign() != 0 {
		return rlpHash([]interface{}{
			tx.Nonce,
			tx.GasPrice,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
			chainID, uint(0), uint(0),
		})
	}
	return rlpHash([]interface{}{
		tx.Nonce,
		tx.GasPrice,
		tx.Gas,
		tx.To,
		tx.Value,
		tx.Data,
	})
}
*/

func (tx DepositTransaction) Type() byte { return DepositTxType }

func (tx DepositTransaction) RawSignatureValues() (*uint256.Int, *uint256.Int, *uint256.Int) {
	log.Warn("MMDBG dtX RawSignatureValues")
	return uint256.NewInt(0),uint256.NewInt(0),uint256.NewInt(0)
}

func (tx DepositTransaction) GetChainID() *uint256.Int {
	log.Warn("MMDBG dtX GetChainID")
	return new(uint256.Int).SetUint64(901) // FIXME
}
func (tx DepositTransaction) GetSender() (common.Address, bool) {
	return *tx.From, true
}
func (tx DepositTransaction) GetTo() (*common.Address) {
	return tx.To
}

func (tx DepositTransaction) GetValue() *uint256.Int {
	return tx.Value
}

func (tx DepositTransaction) IsContractDeploy() bool {
	return false
}
func (tx DepositTransaction) IsStarkNet() bool {
	return false
}

func (tx *DepositTransaction) Sender(signer Signer) (common.Address, error) {
	return *tx.From, nil
}
func (tx *DepositTransaction) SetSender(addr common.Address) {
	log.Warn("MMDBG dtX SetSender")
	// NOP - FIXME? ct.from.Store(addr)
}
