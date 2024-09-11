// Copyright 2014 The go-ethereum Authors
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

// Package types contains data types related to Ethereum consensus.
package types

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	rlp2 "github.com/ledgerwatch/erigon-lib/rlp"
	"github.com/ledgerwatch/erigon-lib/types/clonable"
	"github.com/ledgerwatch/erigon/rlp"
)

type RejectedTransaction struct {
	// The raw data of the transaction. This allows us to include even completely malformed data
	// blobs that were forced into the sequence by end users as rejected transactions.
	Data []byte `json:"data"`
	// The position in the block at which this tranaction would have appeared had it been valid.
	Pos uint64 `json:"pos"`
}

func (r *RejectedTransaction) EncodingSize() int {
	encodingSize := 0
	encodingSize += rlp2.StringLen(r.Data)
	encodingSize++
	encodingSize += rlp.IntLenExcludingHead(r.Pos)
	return encodingSize
}

func (r *RejectedTransaction) EncodeRLP(w io.Writer) error {
	encodingSize := r.EncodingSize()

	var b [33]byte
	if err := EncodeStructSizePrefix(encodingSize, w, b[:]); err != nil {
		return err
	}

	if err := rlp.EncodeString(r.Data, w, b[:]); err != nil {
		return err
	}
	if err := rlp.EncodeInt(r.Pos, w, b[:]); err != nil {
		return err
	}

	return nil
}

func (r *RejectedTransaction) DecodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		return err
	}

	if r.Data, err = s.Bytes(); err != nil {
		return fmt.Errorf("read Data: %w", err)
	}
	if r.Pos, err = s.Uint(); err != nil {
		return fmt.Errorf("read Pos: %w", err)
	}

	return s.ListEnd()
}

func (*RejectedTransaction) Clone() clonable.Clonable {
	return &RejectedTransaction{}
}

// RejectedTransactions is a list of rejected transactions.
type RejectedTransactions []*RejectedTransaction

func (r RejectedTransactions) Len() int { return len(r) }

func (r RejectedTransactions) EncodeIndex(i int, w *bytes.Buffer) {
	rlp.Encode(w, r[i])
}

func decodeRejected(appendList *[]*RejectedTransaction, s *rlp.Stream) error {
	var err error
	if _, err = s.List(); err != nil {
		if errors.Is(err, rlp.EOL) {
			*appendList = nil
			return nil // EOL, check for ListEnd is in calling function
		}
		return err
	}
	for err == nil {
		var w RejectedTransaction
		if err = w.DecodeRLP(s); err != nil {
			break
		}
		*appendList = append(*appendList, &w)
	}
	return checkErrListEnd(s, err)
}
