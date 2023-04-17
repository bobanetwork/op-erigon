// (insert license+copyright statement)

package vm

import (
//	"sync/atomic"
	"math/big"
	"golang.org/x/crypto/sha3"
	"crypto/rand"
	"github.com/holiman/uint256"
	"bytes"
	"time"

//	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"

//	"github.com/ledgerwatch/erigon/common/u256"
//	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
//	"github.com/ledgerwatch/erigon/crypto"
//	"github.com/ledgerwatch/erigon/params"
	"github.com/ledgerwatch/erigon/rpc"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/log/v3"
	"github.com/ledgerwatch/erigon/common/hexutil"
)

// Hybrid Compute extension
type HCContext struct {
	HcFlag   int
	ReqHash  *libcommon.Hash
	Request  []byte
	Response []byte
	MayBlock bool
	Failed bool
	Caller   libcommon.Address
}

var HCResponseCache map[libcommon.Hash] *HCContext
var HCActive map[libcommon.Hash] *HCContext

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

func HCSimpleRandom() ([]byte, error) {
	//var hcData []byte = []byte{151, 80, 9, 113}

	// Pasted from legacy l2geth
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
	rNum256,_ := uint256.FromBig(randomBigInt)
	rNum32 := rNum256.Bytes32()
	//hcData = append(hcData, rNum32[:]...) 

	//return hcData, nil
	return rNum32[:], nil
}

func HCRequest(req []byte, caller libcommon.Address) ([]byte, error) {
	log.Debug("MMDBG-HC Request", "req", req)
	
	if len(req) == 4 && bytes.Equal(req, []byte{125,191,124,16}) {
		log.Debug("MMDBG-HC SimpleRandom v0")
		return HCSimpleRandom()
	}
	if len(req) < 36 {
		log.Warn("MMDBG-HC Request too short", "req", req)
		return nil,ErrHCFailed
	}
	method := req[0:4]
	version := big.NewInt(0).SetBytes(req[4:36])
	log.Debug("MMDBG-HC Request", "method", method, "version", version)
	

	if version.Cmp(big.NewInt(1)) != 0 && version.Cmp(big.NewInt(65537)) != 0{
		log.Debug("MMDBG-HC Unknown request version", "ver", version)
		return nil, ErrHCFailed
	}
	
	// We now expect to have an ABI-encoded (url_string, payload_bytes)

	t1,_ := abi.NewType("uint32","",nil)
	t4,_ := abi.NewType("address","",nil)
	t2,_ := abi.NewType("string","",nil)
	t3,_ := abi.NewType("bytes","",nil)
	
	dec,err := (abi.Arguments{{Type: t1}, {Type: t4}, {Type: t2}, {Type: t3}}).Unpack(req[4:])
	log.Debug("MMDBG-HC ABI decode", "dec", dec, "err", err)

	if err != nil {
		log.Warn("MMDBG-HC Request decode failed", "err", err)
		return nil, ErrHCFailed
	}
	
	reqUrl := dec[2].(string)
	reqMethod := dec[1].(libcommon.Address)
	reqPayload := dec[3].([]byte)

	hasher := sha3.NewLegacyKeccak256()

	hasher.Write(req[32:36]) // Version as a uint32
	log.Debug("MMDBG-HC hWrite", "ver32", hexutil.Bytes(req[32:36]))
	hasher.Write(reqMethod.Bytes())
	log.Debug("MMDBG-HC hWrite", "reqMethod", hexutil.Bytes(reqMethod.Bytes()))
	hasher.Write([]byte(reqUrl))
	log.Debug("MMDBG-HC hWrite", "url", hexutil.Bytes([]byte(reqUrl)))
	hasher.Write(reqPayload)
	log.Debug("MMDBG-HC hWrite", "payload", hexutil.Bytes(reqPayload))
	reqKey := libcommon.BytesToHash(hasher.Sum(nil))
	
	encPayload := hexutil.Bytes(reqPayload)
	log.Debug("MMDBG-HC Request", "ver", version.Uint64(), "reqKey", reqKey, "reqUrl", reqUrl, "reqMethod", reqMethod, "encPayload", encPayload)

	var responseBytes []byte
	
	if version.Cmp(big.NewInt(1)) == 0 {
		// Offchain
		client, err := rpc.Dial(reqUrl)

		if err != nil {
			log.Warn("MMDBG-HC Dial failure", "err", err, "url", reqUrl)
			return nil, ErrHCFailed
		}
	
		var responseStringEnc string
		err = client.Call(&responseStringEnc, reqMethod.Hex(), /* time.Duration(1200)*time.Millisecond, */ encPayload)
		if err != nil {
			log.Debug("MMDBG-HC ClientCall failed", "err", err, "resp", responseStringEnc)
			return nil, ErrHCFailed
		}
		log.Debug("MMDBG-HC ClientCall result", "responseStringEnc", responseStringEnc)
		responseBytes, err = hexutil.Decode(responseStringEnc)
		if err != nil {
			log.Warn("MMDBG-HC Response decode failed", "err", err)
			return nil, ErrHCFailed
		}
	} else if version.Cmp(big.NewInt(65537)) == 0 {
		// SimpleRandom
		responseBytes,err = HCSimpleRandom()
		if err != nil {
			log.Warn("MMDBG-HC SimpleRandom failed", "err", err)
			return nil, ErrHCFailed
		}
	}

	var hcData []byte = []byte{223, 201, 138, 232}

	p1,_ := abi.NewType("bytes32","",nil)
	p2,_ := abi.NewType("bytes", "", nil)
	
	resp, err := (abi.Arguments{{Type: p1}, {Type: p2}}).Pack([32]byte(reqKey), responseBytes[:])

	if err != nil {
		log.Warn("MMDBG-HC Response encode failed", "err", err)
		return nil, ErrHCFailed
	}
	
	hcData = append(hcData, resp...)
	log.Debug("MMDBG-HC Response", "hcData", hexutil.Bytes(hcData))

	return hcData,nil
}

func DoOffchain(hc *HCContext) error {
	time.Sleep(2 * time.Second)
	log.Debug("MMDBG-HC call.go Sleep done")

	hcData, err := HCRequest(hc.Request, hc.Caller)
	hc.Response = make([]byte, len(hcData))
	copy(hc.Response, hcData)

//result, err = core.ApplyMessage(r.evm, r.message, gp, true /* refunds */, false /* gasBailout */)
//log.Debug("MMDBG-HC call.go after ApplyMessage2", "err", err, "result", result)
	if err == nil {
		hc.HcFlag = 2
	} else {
		hc.HcFlag = 4
		hc.Failed = true
	}
	return err
}

// Called after an EVM run to look for a trigger event
func CheckTrigger(hc *HCContext, input []byte, ret []byte, err error) bool {
	if hc == nil || hc.Failed || hc.HcFlag != 0 {
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
		return bytes.Equal(ret[68:68 + len(trigger)], trigger)
	}
	log.Debug("MMDBG-HC CheckTrigger reverted without trigger string", "ret", hexutil.Bytes(ret))
	return false
}
