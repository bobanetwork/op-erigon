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
	"testing"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/hexutility"
	"github.com/ledgerwatch/erigon/common"
	"github.com/ledgerwatch/erigon/rlp"
)

var rt = RejectedTransaction{
	Data: []byte{0x01, 0x02, 0x03},
	Pos:  1,
}

var rts = RejectedTransactions{
	{
		Data: []byte{0x01, 0x02, 0x03},
		Pos:  1,
	},
	{
		Data: []byte{0x04, 0x05, 0x06},
		Pos:  2,
	},
}

func TestEncoding(t *testing.T) {
	t.Parallel()
	enc := rt.EncodingSize()
	if enc != 5 {
		t.Errorf("expected 5, got %d", enc)
	}
}

func TestEncodeRLP(t *testing.T) {
	// Encode the RejectedTransaction to RLP
	var buf bytes.Buffer
	err := rt.EncodeRLP(&buf)
	if err != nil {
		t.Fatalf("EncodeRLP failed: %v", err)
	}

	// Expected RLP encoding
	expected := []byte{
		// RLP encoding of the struct size prefix
		0xc5,
		0x83,
		// Data field
		0x01, 0x02, 0x03,
		// Pos field
		0x01,
	}

	// Compare the encoded result with the expected result
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("EncodeRLP result mismatch.\nExpected: %x\nGot: %x", expected, buf.Bytes())
	}
}

func TestEncodeDecodeRLP(t *testing.T) {
	// Encode the RejectedTransaction to RLP
	writer := bytes.NewBuffer(nil)
	err := rt.EncodeRLP(writer)
	if err != nil {
		t.Fatalf("EncodeRLP failed: %v", err)
	}
	rlpBytes := libcommon.CopyBytes(writer.Bytes())
	writer.Reset()
	writer.WriteString(hexutility.Encode(rlpBytes))

	// Decode the RLP-encoded data back into a RejectedTransaction instance
	var decoded RejectedTransaction
	fromHex := libcommon.CopyBytes(common.FromHex(writer.String()))
	bodyReader := bytes.NewReader(fromHex)
	stream := rlp.NewStream(bodyReader, 0)
	err = decoded.DecodeRLP(stream)
	if err != nil {
		t.Fatalf("DecodeRLP failed: %v", err)
	}

	// Verify that the decoded instance matches the original instance
	if !bytes.Equal(decoded.Data, rt.Data) {
		t.Errorf("Data mismatch.\nExpected: %x\nGot: %x", rt.Data, decoded.Data)
	}
	if decoded.Pos != rt.Pos {
		t.Errorf("Pos mismatch.\nExpected: %d\nGot: %d", rt.Pos, decoded.Pos)
	}
}
