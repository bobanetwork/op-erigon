// (insert license+copyright statement)

package vm

import (
	//	"sync/atomic"
	"bytes"
	"crypto/rand"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
	"math/big"
	"time"

	//	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"

	//	"github.com/ledgerwatch/erigon/common/u256"
	//	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
	//	"github.com/ledgerwatch/erigon/crypto"
	//	"github.com/ledgerwatch/erigon/params"
	"github.com/ledgerwatch/erigon-lib/common/hexutility"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/common/hexutil"
	"github.com/ledgerwatch/erigon/rpc"
	"github.com/ledgerwatch/log/v3"
)

/* Hybrid Compute extension. Used to capture information when an offchain operation is triggered
   and pass that information to the code which generates the offchain transaction to populate the
   result map in the helper contract. The "State" variable tracks phases of the operation:
     0 - Transaction has not yet invoked Hybrid Compute
     1 - A trigger was detected when an EVM operation reverted
     2 - An offchain result has been obtained and is ready to be applied
     3 - An offchain Tx has been inserted ahead of the current Tx
     4 - The HybridCompute interaction failed and will not be retried. The Tx will revert back to the caller
         with a "GetResponse: Missing cache entry" result. This category applies only to failures in the
	 Hybrid Compute mechanism itself. Where possible, other types of error will be reported in-band through
	 the "success" parameter and a descriptive error message.

*/

type HCContext struct {
	State    int
	ReqHash  *libcommon.Hash
	Request  []byte
	Response []byte
	Caller   libcommon.Address
}

var HCResponseCache map[libcommon.Hash]*HCContext
var HCActive map[libcommon.Hash]*HCContext

func HCKey(addr libcommon.Address, nonce uint64, data []byte) libcommon.Hash {
	var bNonce big.Int
	bNonce.SetUint64(nonce)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(addr.Bytes())
	// hasher.Write(bNonce.Bytes()) // FIXME
	hasher.Write(data)
	key := libcommon.BytesToHash(hasher.Sum(nil))
	//log.Debug("MMDBG-HC HCKey", "key", key, "addr", addr, "nonce", nonce, "dataPrefix", hexutility.Bytes(data[:4]))

	return key
}

func HCSimpleRandom() ([]byte, error) {
	// Copied from legacy l2geth
	// Generate cryptographically strong pseudo-random int between 0 - 2^256 - 1
	one := big.NewInt(1)
	two := big.NewInt(2)
	max := new(big.Int)
	// Max random value 2^256 - 1
	max = max.Exp(two, big.NewInt(int64(256)), nil).Sub(max, one)

	randomBigInt, err := rand.Int(rand.Reader, max)

	if err != nil {
		log.Error("MMDBG-HC TURING bobaTuringRandom:Random Number Generation Failed", "err", err)
		return nil, err
	}

	log.Debug("MMDBG-HC TURING bobaTuringRandom:Random number",
		"randomBigInt", randomBigInt)

	// rNum32 := uint256.MustFromBig(randomBigInt).Bytes32() // Needs uint256 pkg 1.2.2
	rNum256, _ := uint256.FromBig(randomBigInt)
	rNum32 := rNum256.Bytes32()

	return rNum32[:], nil
}


// This function attempts to perform the offchain JSON-RPC request and to parse the response.
// Errors here will be passed back to the caller and will not trigger ErrHCFailed.
// TODO - redirect outgoing requests through an external proxy (squid, socks5, etc).

func DoOffchain (reqUrl string, reqMethod libcommon.Address, reqPayload []byte) ([]byte, uint32) {
	// Debugging - simulate a slow offchain response
	time.Sleep(2 * time.Second)
	log.Debug("MMDBG-HC Sleep done")

	// Offchain
	client, err := rpc.Dial(reqUrl)

	if err != nil {
		log.Warn("MMDBG-HC Dial failure", "err", err, "url", reqUrl)
		return []byte(err.Error()), 1001
	}

	var responseStringEnc string
	var responseBytes []byte
	
	encPayload := hexutility.Bytes(reqPayload)
	log.Debug("MMDBG-HC DoOffchain", "reqUrl", reqUrl, "reqMethod", reqMethod, "encPayload", encPayload)

	err = client.Call(&responseStringEnc, reqMethod.Hex() /* time.Duration(1200)*time.Millisecond, */, encPayload)
	if err != nil {
		log.Debug("MMDBG-HC ClientCall failed", "err", err, "resp", responseStringEnc)
		return []byte(err.Error()), 1002
	}
	log.Debug("MMDBG-HC ClientCall result", "responseStringEnc", responseStringEnc)
	responseBytes, err = hexutil.Decode(responseStringEnc)
	if err != nil {
		log.Warn("MMDBG-HC Response decode failed", "err", err)
		return []byte(err.Error()), 1003
	}
	return responseBytes, 0
}

func HCRequest(hc *HCContext) error {

	log.Debug("MMDBG-HC Request", "req", hc.Request)

	if len(hc.Request) < 36 {
		log.Warn("MMDBG-HC Request too short", "req", hc.Request)
		hc.State = 4
		return ErrHCFailed
	}
	method := hc.Request[0:4]
	version := big.NewInt(0).SetBytes(hc.Request[4:36])
	log.Debug("MMDBG-HC Request", "method", method, "version", version)

	if version.Cmp(big.NewInt(1)) != 0 && version.Cmp(big.NewInt(65537)) != 0 {
		log.Debug("MMDBG-HC Unknown request version", "ver", version)
		hc.State = 4
		return ErrHCFailed
	}

	// We now expect to have an ABI-encoded (url_string, payload_bytes)
	var (
		tAddress,_ = abi.NewType("address", "", nil)
		tBytes,_   = abi.NewType("bytes", "", nil)
		tBytes32,_ = abi.NewType("bytes32", "", nil)
		tString,_  = abi.NewType("string", "", nil)
		tUint32,_  = abi.NewType("uint32", "", nil)
	)
	dec, err := (abi.Arguments{{Type: tUint32}, {Type: tAddress}, {Type: tString}, {Type: tBytes}}).Unpack(hc.Request[4:])
	log.Debug("MMDBG-HC ABI decode", "dec", dec, "err", err)

	if err != nil {
		log.Warn("MMDBG-HC Request decode failed", "err", err)
		hc.State = 4
		return ErrHCFailed
	}

	reqUrl := dec[2].(string)
	reqMethod := dec[1].(libcommon.Address)
	reqPayload := dec[3].([]byte)

	hasher := sha3.NewLegacyKeccak256()

	hasher.Write(hc.Request[32:36]) // Version as a uint32
	log.Debug("MMDBG-HC hWrite", "ver32", hexutility.Bytes(hc.Request[32:36]))
	hasher.Write(reqMethod.Bytes())
	log.Debug("MMDBG-HC hWrite", "reqMethod", hexutility.Bytes(reqMethod.Bytes()))
	hasher.Write([]byte(reqUrl))
	log.Debug("MMDBG-HC hWrite", "url", hexutility.Bytes([]byte(reqUrl)))
	hasher.Write(reqPayload)
	log.Debug("MMDBG-HC hWrite", "payload", hexutility.Bytes(reqPayload))
	reqKey := libcommon.BytesToHash(hasher.Sum(nil))

	var responseCode uint32 // 0 = success
	var responseBytes []byte
	log.Debug("MMDBG-HC Request", "ver", version.Uint64(), "reqKey", reqKey, "reqUrl", reqUrl, "reqMethod", reqMethod)

	if version.Cmp(big.NewInt(1)) == 0 {
		responseBytes, responseCode = DoOffchain(reqUrl, reqMethod, reqPayload)
		if responseCode == 0 {
			log.Debug("MMDBG-HC DoOffchain failed", "errCode", responseCode, "response", responseBytes)
		}
	} else if version.Cmp(big.NewInt(65537)) == 0 {
		// SimpleRandom
		responseBytes, err = HCSimpleRandom()
		if err != nil {
			log.Warn("MMDBG-HC SimpleRandom failed", "err", err)
			hc.State = 4
			return ErrHCFailed
		}
	}

	hc.Response = []byte{0x11, 0xed, 0xaa, 0xe0} // PutResponse(bytes32,uint32,bytes)


	resp, err := (abi.Arguments{{Type: tBytes32}, {Type: tUint32}, {Type: tBytes}}).Pack([32]byte(reqKey), responseCode, responseBytes[:])

	if err != nil {
		log.Warn("MMDBG-HC Response encode failed", "err", err)
		hc.State = 4
		return ErrHCFailed
	}

	hc.Response = append(hc.Response, resp...)
	log.Debug("MMDBG-HC Response", "hcData", hexutility.Bytes(hc.Response))

	hc.State = 2
	return nil
}
/*
func DoOffchain(hc *HCContext) error {
	time.Sleep(2 * time.Second)
	log.Debug("MMDBG-HC call.go Sleep done")

	hcData, err := HCRequest(hc.Request, hc.Caller)
	hc.Response = make([]byte, len(hcData))
	copy(hc.Response, hcData)

	if err == nil {
		hc.State = 2
	} else {
		hc.State = 4
	}
	return err
}
*/
// Called after an EVM run to look for a trigger event
func CheckTrigger(hc *HCContext, input []byte, ret []byte, err error) bool {
	if hc == nil || hc.State != 0 {
		return false
	}
	// Check the selector for GetResponse(uint32,address,string,bytes)
	if !bytes.Equal(input[:4], []byte{0x8e, 0x5d, 0xc7, 0x65}) {
		return false
	}
	// Check for a revert
	if err != ErrExecutionReverted {
		return false
	}
	// Check for an "Error(string)" selector + the expected trigger string
	if len(ret) >= 100 && bytes.Equal(ret[:4], []byte{0x08, 0xc3, 0x79, 0xa0}) {
		trigger := []byte("GetResponse: Missing cache entry")
		return bytes.Equal(ret[68:68+len(trigger)], trigger)
	}
	log.Debug("MMDBG-HC CheckTrigger reverted without trigger string", "ret", hexutility.Bytes(ret))
	return false
}
