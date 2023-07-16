// (insert license+copyright statement)

package vm

import (
	//	"sync/atomic"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
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
   result map in the helper contract.

   The "State" variable tracks phases of the operation:
     0 - Transaction has not yet invoked Hybrid Compute
     1 - A trigger was detected when an EVM operation reverted
     2 - An offchain result has been obtained and is ready to be applied
     3 - An offchain Tx has been inserted ahead of the current Tx
     4 - The HybridCompute interaction failed and will not be retried. The Tx will revert back to the caller
         with a "GetResponse: Missing cache entry" result. This category applies only to failures in the
	 Hybrid Compute mechanism itself. Where possible, other types of error will be reported in-band through
	 the "success" parameter and a descriptive error message.

*/

const (
	HC_OP_NONE = iota
	HC_OFFCHAIN_V1
	HC_RANDOM_V1
	HC_RANDOMSEQ_V1
	HC_LEGACY_RANDOM
	HC_LEGACY_OFFCHAIN
)

// Maximum length of hex-encoded response string
const HC_MAX_ENC = 16384

type HCContext struct {
	State  int
	OpType int
	Caller libcommon.Address
	//ReqHash  *libcommon.Hash
	Request  []byte
	Response []byte
}

var HCResponseCache map[libcommon.Hash]*HCContext
var HCActive map[libcommon.Hash]*HCContext

// Generate a key which will be used to associate an HCContext to a transaction. We need to keep the
// same context during each iteration of eth_estimateGas (if any) as well as when the real transaction
// is submitted. However we do not carry over a context if the user changes the nonce, destination addr,
// or input data from one call to another.
// Cache entries are removed when eth_sendRawTransaction finishes or on a periodic cleanup timer for
// transactions which were abandoned after gas estimation.

func HCKey(fromAddr libcommon.Address, toPtr *libcommon.Address, nonce uint64, data []byte) libcommon.Hash {
	bNonce := make([]byte, 8)
	binary.BigEndian.PutUint64(bNonce, nonce)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(fromAddr.Bytes())

	var toAddr libcommon.Address
	if toPtr != nil {
		toAddr = *toPtr
	}
	hasher.Write(toAddr.Bytes())
	hasher.Write(bNonce)
	hasher.Write(data)
	key := libcommon.BytesToHash(hasher.Sum(nil))
	if toAddr != libcommon.HexToAddress("0x4200000000000000000000000000000000000015") && toAddr != libcommon.HexToAddress("0xc0d3C0D3C0D3c0D3C0D3C0d3C0D3c0D3c0d30015") {
		log.Debug("MMDBG-HC HCKey", "key", key, "from", fromAddr, "to", toAddr, "nonce", nonce, "data", hexutility.Bytes(data))
	}
	return key
}

// Copied from our current l2geth. This returns a random number which may be suitable for some applications.
// Note however that, as with all Hybrid Compute operations, the computation is performed once and then the
// same result is re-used for any subsequent calls referring to that transaction. Therefore it may be possible
// for a user to determine the "random" value during an eth_estimateGas() call and only submit a real transaction
// if the chosen value would represent a favorable outcome.

func HCGenerateRandom() (*uint256.Int, error) {
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

	ret256 := uint256.MustFromBig(randomBigInt)
	return ret256, nil
}

// This function attempts to perform the offchain JSON-RPC request and to parse the response.
// Errors here will be passed back to the caller and will not trigger ErrHCFailed.
// TODO - redirect outgoing requests through an external proxy (squid, socks5, etc).

func DoOffchain(reqUrl string, reqMethod libcommon.Address, reqPayload []byte) ([]byte, uint32) {
	// Debugging - simulate a slow offchain response
	time.Sleep(2 * time.Second)
	log.Debug("MMDBG-HC Sleep done")

	// Offchain
	client, err := rpc.Dial(reqUrl, log.New())

	if err != nil {
		log.Warn("MMDBG-HC Dial failure", "err", err, "url", reqUrl)
		return []byte(err.Error()), 1001 // FIXME - redefine error codes and merge with legacy Turing errors.
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

	if len(responseStringEnc) > HC_MAX_ENC {
		log.Warn("MMDBG-HC Encoded response too long", "len", len(responseStringEnc))
		return []byte("Encoded response too long"), 1004
	}

	responseBytes, err = hexutil.Decode(responseStringEnc)
	if err != nil {
		log.Warn("MMDBG-HC Response decode failed", "err", err)
		return []byte(err.Error()), 1003
	}
	return responseBytes, 0
}

// Multi-transaction secure RNG, using a commit/reveal approach. Client and server each start by
// generating a random number and revealing its hash. In the next transaction, client reveals its
// secret and the server returns a result which is the XOR of its secret and the client secret.
// Hashes are checked to ensure that the secrets are the same ones generated in the original Tx.
//
// Note that a client may still choose to abandon a Tx after an eth_estimateGas() if the result is
// undesirable. However they cannot undo the first Tx in which the hashes were committed.
//
// This operation may fail if the Sequencer node loses its private state between calls (e.g. in the
// event of database corruption).
//
// A future version may be extended to a 3-way XOR including an off-chain endpoint.

type RandomCacheEntry struct {
	expectedHash libcommon.Hash
	secret       *uint256.Int
	commitBN     uint64
}

var randomCache map[libcommon.Hash]*RandomCacheEntry

func DoRandomSeq(caller libcommon.Address, session [32]byte, cNext libcommon.Hash, cNum *uint256.Int, blockNumber uint64) (*libcommon.Hash, *uint256.Int, error) {
	var err error
	var found bool
	var zeroHash libcommon.Hash

	var result uint256.Int
	var sNext libcommon.Hash

	var thisCE *RandomCacheEntry
	var nextCE *RandomCacheEntry
	var nextKey libcommon.Hash
	var doStore bool

	var commitDepth uint64 = 1 // TODO - could make this configurable somehow, or could hardcode it

	if randomCache == nil {
		randomCache = make(map[libcommon.Hash]*RandomCacheEntry)
	}

	if cNext != zeroHash {
		// Prepare for the next transaction.

		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(caller.Bytes())
		hasher.Write(session[:])
		hasher.Write(cNext.Bytes())
		nextKey = libcommon.BytesToHash(hasher.Sum(nil))

		nextCE, found = randomCache[nextKey]

		if !found {
			nextCE = new(RandomCacheEntry)
			nextCE.secret, err = HCGenerateRandom()
			nextCE.commitBN = blockNumber
			if err != nil {
				log.Warn("MMDBG-HC HCGenerateRandom() failed", "err", err)
				return nil, nil, errors.New("HCGenerateRandom failed")
			}
			log.Debug("MMDBG-HC Generated new secret for", "key", nextKey, "blockNumber", blockNumber)
			doStore = true
		} else {
			log.Debug("MMDBG-HC randomCache hit for", "key", nextKey, "commitBN", nextCE.commitBN, "BN", blockNumber)
			if blockNumber > nextCE.commitBN {
				nextCE.commitBN = blockNumber
			}
		}
		hasher = sha3.NewLegacyKeccak256()
		sTmp := nextCE.secret.Bytes32()
		hasher.Write(sTmp[:])
		sNext = libcommon.BytesToHash(hasher.Sum(nil))
	}

	if !cNum.IsZero() {
		h2 := sha3.NewLegacyKeccak256()
		cTmp := cNum.Bytes32()
		h2.Write(cTmp[:])
		cHash := new(libcommon.Hash)
		cHash.SetBytes(h2.Sum(nil))

		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(caller.Bytes())
		hasher.Write(session[:])
		hasher.Write(cHash.Bytes())
		thisKey := libcommon.BytesToHash(hasher.Sum(nil))
		log.Debug("MMDBG-HC will check randomCache for", "cNum", cNum, "key", thisKey)

		thisCE, found = randomCache[thisKey]
		if !found {
			log.Debug("MMDBG-HC Cache entry not found for", "key", thisKey)
			return nil, nil, errors.New("DoRandomSeq state not found")
		} else if blockNumber < thisCE.commitBN+commitDepth {
			log.Debug("MMDBG-HC Invalid block number for DoRandomSeq", "expected", thisCE.commitBN, "actual", blockNumber)
			return nil, nil, errors.New("DoRandomSeq invalid block number")
		} else {
			result.Xor(cNum, thisCE.secret)
		}
	}

	if doStore {
		log.Debug("MMDBG-HC DoRandomSeq storing cache entry", "key", nextKey, "ce", nextCE)
		randomCache[nextKey] = nextCE
	}

	log.Debug("MMDBG-HC DoRandomSeq successful", "sNext", sNext, "result", result)
	return &sNext, &result, nil
}

func HCRequest(hc *HCContext, blockNumber uint64) error {
	log.Debug("MMDBG-HC Request", "req", hexutility.Bytes(hc.Request))

	var (
		//tAddress,_ = abi.NewType("address", "", nil)
		tBytes, _   = abi.NewType("bytes", "", nil)
		tBytes32, _ = abi.NewType("bytes32", "", nil)
		tString, _  = abi.NewType("string", "", nil)
		tUint32, _  = abi.NewType("uint32", "", nil)
		tUint256, _ = abi.NewType("uint256", "", nil)
		tBool, _    = abi.NewType("bool", "", nil)
	)

	var responseCode uint32 // 0 = success
	var responseBytes []byte
	var reqKey libcommon.Hash
	var err error
	hasher := sha3.NewLegacyKeccak256()

	switch hc.OpType {
	case HC_RANDOM_V1:
		// SimpleRandom
		r256, err := HCGenerateRandom()
		if err != nil {
			log.Warn("MMDBG-HC SimpleRandom failed", "err", err)
			hc.State = 4
			return ErrHCFailed
		}
		r32 := r256.Bytes32()
		responseBytes = r32[:]

		hasher.Write([]byte{0xc6, 0xe4, 0xb0, 0xd3})
		hasher.Write(hc.Caller.Bytes())
	case HC_LEGACY_RANDOM:
		// SimpleRandom
		r256, err := HCGenerateRandom()
		if err != nil {
			log.Warn("MMDBG-HC LegacyRandom failed", "err", err)
			hc.State = 4
			return ErrHCFailed
		}
		r32 := r256.Bytes32()
		responseBytes = r32[:]

		hasher.Write([]byte{0x49, 0x3d, 0x57, 0xd6})
		hasher.Write(hc.Caller.Bytes())
	case HC_OFFCHAIN_V1:
		// We now expect to have an ABI-encoded (url_string, payload_bytes)
		dec, err := (abi.Arguments{{Type: tString}, {Type: tBytes}}).Unpack(hc.Request[4:])
		log.Debug("MMDBG-HC ABI decode (offchain)", "dec", dec, "err", err, "hc", hc)

		if err != nil {
			log.Warn("MMDBG-HC Request decode failed", "err", err)
			hc.State = 4
			return ErrHCFailed
		}
		reqUrl := dec[0].(string)
		reqMethod := hc.Caller
		reqPayload := dec[1].([]byte)

		hasher.Write([]byte{0xc1, 0xfd, 0x7e, 0x46})
		hasher.Write(hc.Caller.Bytes())
		hasher.Write([]byte(reqUrl))
		hasher.Write(reqPayload)

		log.Debug("MMDBG-HC Request", "reqUrl", reqUrl, "reqMethod", reqMethod)
		responseBytes, responseCode = DoOffchain(reqUrl, reqMethod, reqPayload)
		if responseCode != 0 {
			log.Debug("MMDBG-HC DoOffchain failed", "errCode", responseCode, "response", responseBytes)
		}
		log.Debug("MMDBG-HC Request", "responseCode", responseCode, "responseBytes", hexutility.Bytes(responseBytes))
	case HC_LEGACY_OFFCHAIN:
		dec, err := (abi.Arguments{{Type: tUint32}, {Type: tString}, {Type: tBytes}}).Unpack(hc.Request[4:])
		log.Debug("MMDBG-HC ABI decode (offchain)", "dec", dec, "err", err, "hc", hc)

		legacyVersion := dec[0].(uint32)
		log.Debug("MMDBG-HC Legacy Offchain call", "version", legacyVersion)

		if err != nil {
			log.Warn("MMDBG-HC Request decode failed", "err", err)
			hc.State = 4
			return ErrHCFailed
		}
		reqUrl := dec[1].(string)
		reqMethod := hc.Caller
		reqPayload := dec[2].([]byte)

		hasher.Write([]byte{0x7d, 0x93, 0x61, 0x6c})
		hasher.Write(hc.Caller.Bytes())
		hasher.Write([]byte(reqUrl))
		hasher.Write(reqPayload)

		if legacyVersion == 1 {
			// Originally a Length field was prepended to the offchain request and response.
			pLen := uint32(len(reqPayload))
			prefix, err := (abi.Arguments{{Type: tUint32}}).Pack(pLen)
			if err != nil {
				log.Warn("MMDBG-HC Legacy-encode failed", "err", err)
				hc.State = 4
				return ErrHCFailed
			}
			reqPayload = append(prefix, reqPayload...)
			log.Debug("MMDBG-HC legacyVersion new payload", "reqPayload", reqPayload)
		}

		log.Debug("MMDBG-HC Legacy Request", "reqUrl", reqUrl, "reqMethod", reqMethod)
		responseBytes, responseCode = DoOffchain(reqUrl, reqMethod, reqPayload)
		if responseCode != 0 {
			log.Debug("MMDBG-HC LegacyOffchain failed", "errCode", responseCode, "response", responseBytes)
		}
		log.Debug("MMDBG-HC Legacy Request (1)", "responseCode", responseCode, "responseBytes", hexutility.Bytes(responseBytes))

		if legacyVersion == 1 {
			responseLen := new(big.Int).SetBytes(responseBytes[:32])
			responseBytes = responseBytes[32:]

			if responseLen.Cmp(big.NewInt(int64(len(responseBytes)))) != 0 {
				log.Warn("MMDBG-HC Legacy-decode length mismatch", "expected", responseLen, "actual", len(responseBytes))
				hc.State = 4
				return ErrHCFailed
			}
		}
		log.Debug("MMDBG-HC Legacy Request (2)", "responseCode", responseCode, "responseBytes", hexutility.Bytes(responseBytes))
	case HC_RANDOMSEQ_V1:
		dec, err := (abi.Arguments{{Type: tBytes32}, {Type: tBytes32}, {Type: tUint256}}).Unpack(hc.Request[4:])
		if err != nil {
			log.Warn("MMDBG-HC Request decode failed", "err", err)
			hc.State = 4
			return ErrHCFailed
		}
		log.Debug("MMDBG-HC ABI decode (randomseq)", "dec", dec, "err", err, "BN", blockNumber, "hc", hc)

		session := dec[0].([32]byte)
		chBytes := dec[1].([32]byte)
		clientHash := libcommon.BytesToHash(chBytes[:])
		var clientNum *uint256.Int
		clientNum = uint256.MustFromBig(dec[2].(*big.Int))

		log.Debug("MMDBG-HC ABI decode (randomseq)", "session", hexutility.Bytes(session[:]), "clientHash", clientHash, "clientNum", clientNum)

		hasher.Write([]byte{0x32, 0xbe, 0x42, 0x8f})
		hasher.Write(hc.Caller.Bytes())
		hasher.Write(session[:])
		hasher.Write(clientHash.Bytes())
		cTmp := clientNum.Bytes32()
		hasher.Write(cTmp[:])

		sNext, resultNum, err := DoRandomSeq(hc.Caller, session, clientHash, clientNum, blockNumber)

		if err == nil {
			xHash := *sNext
			xNum := resultNum.ToBig()
			responseBytes, err = (abi.Arguments{{Type: tBytes32}, {Type: tUint256}}).Pack([32]byte(xHash), xNum)
			log.Debug("MMDBG-HC RandomSeq encode", "sNext", xHash, "resultNum", xNum, "err", err, "responseBytes", responseBytes)
		} else {
			responseBytes = nil
			responseCode = 1 // FIXME
		}
		log.Debug("MMDBG-HC RandomSeq result", "err", err, "responseBytes", responseBytes)
	default:
		log.Debug("MMDBG-HC Unknown opType", "opType", hc.OpType)
		hc.State = 4
		return ErrHCFailed
	}

	reqKey = libcommon.BytesToHash(hasher.Sum(nil))
	log.Debug("MMDBG-HC Request", "reqKey", reqKey)

	//hc.Response = []byte{0x11, 0xed, 0xaa, 0xe0} // PutResponse(bytes32,uint32,bytes)
	hc.Response = []byte{0xeb, 0x65, 0x98, 0xb5} // PutResponse(bytes32,bool,bytes)

	var success bool
	if responseCode == 0 {
		success = true
	}

	resp, err := (abi.Arguments{{Type: tBytes32}, {Type: tBool}, {Type: tBytes}}).Pack([32]byte(reqKey), success, responseBytes)

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

// Called after an EVM run to look for a trigger event
func CheckTrigger(hc *HCContext, input []byte, ret []byte, err error) bool {
	if hc == nil || hc.State != 0 {
		return false
	}
	// Check for a revert
	if err != ErrExecutionReverted {
		return false
	}
	// Check for an "Error(string)" selector + the expected trigger string
	if len(ret) >= 100 && bytes.Equal(ret[:4], []byte{0x08, 0xc3, 0x79, 0xa0}) {
		trigger := []byte("GetResponse: Missing cache entry")
		if !bytes.Equal(ret[68:68+len(trigger)], trigger) {
			log.Debug("MMDBG-HC CheckTrigger reverted without trigger string", "ret", hexutility.Bytes(ret))
			return false
		}
	}
	// Check the selector for a recognized method
	switch {
	case bytes.Equal(input[:4], []byte{0xc1, 0xfd, 0x7e, 0x46}):
		hc.OpType = HC_OFFCHAIN_V1
	case bytes.Equal(input[:4], []byte{0xc6, 0xe4, 0xb0, 0xd3}):
		hc.OpType = HC_RANDOM_V1
	case bytes.Equal(input[:4], []byte{0x32, 0xbe, 0x42, 0x8f}):
		hc.OpType = HC_RANDOMSEQ_V1
	case bytes.Equal(input[:4], []byte{0x49, 0x3d, 0x57, 0xd6}):
		hc.OpType = HC_LEGACY_RANDOM
	case bytes.Equal(input[:4], []byte{0x7d, 0x93, 0x61, 0x6c}):
		hc.OpType = HC_LEGACY_OFFCHAIN
	default:
		log.Debug("MMDBG-HC noTrigger", "sel", hexutility.Bytes(input[:4]))
		return false
	}
	hc.State = 1
	log.Debug("MMDBG-HC Triggered with", "OpType", hc.OpType)
	return true
}
