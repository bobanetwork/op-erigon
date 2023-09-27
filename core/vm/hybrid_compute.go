// (insert license+copyright statement)

package vm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
	"math/big"
	"sync"
	"time"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/hexutility"
	"github.com/ledgerwatch/erigon/accounts/abi"
	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
	"github.com/ledgerwatch/erigon/common/hexutil"
	"github.com/ledgerwatch/erigon/rpc"
	"github.com/ledgerwatch/log/v3"
)

type HcState int

// Maximum length of hex-encoded response string
const HC_MAX_ENC = 16384
const HC_EXPIRATION = 60 * time.Second

const (
	HC_OP_LEGACY_RANDOM   uint32 = 0x493d57d6 // These are the function selectors from the helper contract
	HC_OP_LEGACY_OFFCHAIN uint32 = 0xd40c48b0
	HC_OP_OFFCHAIN_V1     uint32 = 0xc1fd7e46
	HC_OP_RANDSEQ_V1      uint32 = 0x32be428f

	HC_STATE_NONE      HcState = 0 // Has not yet interacted with Hybrid Compute
	HC_STATE_TRIGGERED HcState = 1 // ErrHcReverted trigger detected
	HC_STATE_READY     HcState = 2 // Offchain Tx has been prepared
	HC_STATE_INSERTED  HcState = 3 // Offchain Tx has been added to block
	HC_STATE_COMPLETED HcState = 4 // FIXME Original Tx has been added after the Offchain Tx
	HC_STATE_FAILED    HcState = 5 // HC mechanism failed (various reasons). Doesn't include in-band errors returned to the client
)

// Error codes associated with a "success=false" returned in the response. Note that this is considered
// a successful delivery for the Sequencer, distinguished from conditions which return ErrHCFailed
var (
	HC_ERR_MISC             = errors.New("HC: Unknown Error")
	HC_ERR_CONNECT          = errors.New("HC: Failed to dial endpoint")
	HC_ERR_CONNECT_PROXY    = errors.New("HC: Cannot reach proxy server") // Reserved for future implementation
	HC_ERR_BAD_REQUEST      = errors.New("HC: Bad Request")               // Endpoint returned a 400-class error
	HC_ERR_ENDPOINT_UNAVAIL = errors.New("HC: Endpoint Unavailable")      // Reserved - Endpoint returned a 500-class error
	HC_ERR_TOO_LONG         = errors.New("HC: Response too long")         // API response greater than HC_MAX_ENC; value subject to change
	HC_ERR_DECODE           = errors.New("HC: Could not decode response")
	HC_ERR_RNG_FAILURE      = errors.New("HC: Failed to generate random number") // RNG failure, including a lost server state for SeqRandom
	HC_ERR_CREDIT_LOW       = errors.New("HC: Insufficient credit")              // Reserved - currently only used inside HCHelper
)

/* Could define additional error codes mapped directly to legacy errors if needed:
   if(rType ==  1) return "TURING: Geth intercept failure";
   if(rType == 10) return "TURING: Incorrect input state";
   if(rType == 11) return "TURING: Calldata too short";
   if(rType == 12) return "TURING: URL >64 bytes";
   if(rType == 13) return "TURING: Server error";
   if(rType == 14) return "TURING: Could not decode server response";
   if(rType == 15) return "TURING: Could not create rpc client";
   if(rType == 16) return "TURING: RNG failure";
   if(rType == 17) return "TURING: API Response too long";
   if(rType == 18) return "TURING: Calldata too long";
   if(rType == 19) return "TURING: Insufficient credit";
   if(rType == 20) return "TURING: Missing cache entry";
*/

type HCContext struct {
	State    HcState
	OpType   uint32
	Caller   libcommon.Address
	Request  []byte
	Response []byte
	ReqNonce uint64
	expires  time.Time
}

type RandomCacheEntry struct {
	expires      time.Time
	expectedHash libcommon.Hash
	secret       *uint256.Int
	commitBN     uint64
}

type HCService struct {
	lock            sync.RWMutex
	randomCache     map[libcommon.Hash]*RandomCacheEntry
	HCResponseCache map[libcommon.Hash]*HCContext
	HCActive        map[libcommon.Hash]*HCContext
}

func NewHCService() (*HCService, error) {
	hcs := &HCService{
		randomCache:     make(map[libcommon.Hash]*RandomCacheEntry),
		HCResponseCache: make(map[libcommon.Hash]*HCContext),
		HCActive:        make(map[libcommon.Hash]*HCContext),
	}
	return hcs, nil
}

func (hcs *HCService) GetHC(key libcommon.Hash) *HCContext {
	hcs.lock.Lock()
	defer hcs.lock.Unlock()
	val, found := hcs.HCResponseCache[key]
	if found {
		return val
	}
	return nil
}

func (hcs *HCService) PutHC(key libcommon.Hash, val *HCContext) {
	hcs.lock.Lock()
	defer hcs.lock.Unlock()
	if val != nil {
		val.expires = time.Now().Add(HC_EXPIRATION)
		hcs.HCResponseCache[key] = val
	} else {
		delete(hcs.HCResponseCache, key)
	}
}

func (hcs *HCService) GetRandom(key libcommon.Hash) *RandomCacheEntry {
	hcs.lock.Lock()
	defer hcs.lock.Unlock()
	val, found := hcs.randomCache[key]
	if found {
		return val
	}
	return nil
}

func (hcs *HCService) PutRandom(key libcommon.Hash, val *RandomCacheEntry) {
	hcs.lock.Lock()
	defer hcs.lock.Unlock()
	if val != nil {
		val.expires = time.Now().Add(HC_EXPIRATION)
		hcs.randomCache[key] = val
	} else {
		delete(hcs.randomCache, key)
	}
}

func (hcs *HCService) PruneCache() {
	hcs.lock.Lock()
	log.Debug("HC checking for stale cache entries", "rcLen", len(hcs.randomCache), "respLen", len(hcs.HCResponseCache), "actLen", len(hcs.HCActive))

	for key, element := range hcs.randomCache {
		if time.Now().After(element.expires) {
			log.Debug("HC removing expired randomCache", "key", key)
			delete(hcs.randomCache, key)
		}
	}

	for key, element := range hcs.HCResponseCache {
		if time.Now().After(element.expires) {
			log.Debug("HC removing expired HCResponseCache", "key", key)
			delete(hcs.randomCache, key)
		}
	}

	hcs.lock.Unlock()
}

// Generate a key which will be used to associate an HCContext to a transaction. We need to keep the
// same context during each iteration of eth_estimateGas (if any) as well as when the real transaction
// is submitted. However we do not carry over a context if the user changes the nonce, destination addr,
// or input data from one call to another.
// Cache entries are removed when eth_sendRawTransaction finishes or on a periodic cleanup timer for
// transactions which were abandoned after gas estimation.
func HCKey(fromAddr libcommon.Address, toPtr *libcommon.Address, ibs evmtypes.IntraBlockState, data []byte) libcommon.Hash {
	// We can't use the nonce field from the msg because it can be 0 on the eth_call() path.
	// Instead we use the current nonce from IntraBlockState
	nonce := ibs.GetNonce(fromAddr)
	bNonce := make([]byte, 8)
	binary.BigEndian.PutUint64(bNonce, nonce)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(fromAddr.Bytes())

	var toAddr libcommon.Address
	if toPtr != nil {
		toAddr = *toPtr
	}
	hasher.Write(toAddr.Bytes())
	//hasher.Write(bNonce)
	hasher.Write(data)
	key := libcommon.BytesToHash(hasher.Sum(nil))
	if toAddr != libcommon.HexToAddress("0x4200000000000000000000000000000000000015") && toAddr != libcommon.HexToAddress("0xc0d3C0D3C0D3c0D3C0D3C0d3C0D3c0D3c0d30015") {
		log.Debug("HC generarated HCKey", "key", key, "from", fromAddr, "to", toAddr, "nonce", nonce)
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
		log.Error("HC bobaTuringRandom:Random Number Generation Failed", "err", err)
		return nil, err
	}

	ret256 := uint256.MustFromBig(randomBigInt)
	return ret256, nil
}

// This function attempts to perform the offchain JSON-RPC request and to parse the response.
// Errors here will be passed back to the caller and will not trigger ErrHCFailed.
// TODO - redirect outgoing requests through an external proxy (squid, socks5, etc).

func DoOffchain(reqUrl string, reqMethod libcommon.Address, reqPayload []byte) ([]byte, error) {
	// TODO - reroute through an external proxy service
	client, err := rpc.Dial(reqUrl, log.New())

	if err != nil {
		log.Warn("HC Dial failure", "err", err, "url", reqUrl)
		return nil, HC_ERR_CONNECT
	}

	var responseStringEnc string
	var responseBytes []byte

	encPayload := hexutility.Bytes(reqPayload)
	log.Debug("HC DoOffchain request", "reqUrl", reqUrl, "reqMethod", reqMethod, "encPayload", encPayload)

	err = client.Call(&responseStringEnc, reqMethod.Hex() /* time.Duration(1200)*time.Millisecond, */, encPayload)
	if err != nil {
		log.Debug("HC ClientCall failed", "err", err, "resp", responseStringEnc)
		return nil, HC_ERR_BAD_REQUEST
	}
	log.Debug("HC ClientCall result", "responseStringEnc", responseStringEnc)

	if len(responseStringEnc) > HC_MAX_ENC {
		log.Warn("HC Encoded response too long", "len", len(responseStringEnc))
		return nil, HC_ERR_TOO_LONG
	}

	responseBytes, err = hexutil.Decode(responseStringEnc)
	if err != nil {
		log.Warn("HC Response decode failed", "err", err)
		return nil, HC_ERR_DECODE
	}
	return responseBytes, nil
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

func DoRandomSeq(hcs *HCService, caller libcommon.Address, session [32]byte, cNext libcommon.Hash, cNum *uint256.Int, blockNumber uint64) (*libcommon.Hash, *uint256.Int, error) {
	var err error
	var zeroHash libcommon.Hash

	var result uint256.Int
	var sNext libcommon.Hash

	var thisCE *RandomCacheEntry
	var nextCE *RandomCacheEntry
	var nextKey libcommon.Hash
	var doStore bool

	var commitDepth uint64 = 1 // TODO - could make this configurable somehow, or could hardcode it

	if cNext != zeroHash {
		// Prepare for the next transaction.

		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(caller.Bytes())
		hasher.Write(session[:])
		hasher.Write(cNext.Bytes())
		nextKey = libcommon.BytesToHash(hasher.Sum(nil))

		nextCE = hcs.GetRandom(nextKey)

		if nextCE == nil {
			nextCE = new(RandomCacheEntry)
			nextCE.secret, err = HCGenerateRandom()
			nextCE.commitBN = blockNumber
			if err != nil {
				log.Warn("HC HCGenerateRandom() failed", "err", err)
				return nil, nil, errors.New("HCGenerateRandom failed")
			}
			log.Debug("HC Generated new secret for", "key", nextKey, "blockNumber", blockNumber)
			doStore = true
		} else {
			log.Debug("HC randomCache hit for", "key", nextKey, "commitBN", nextCE.commitBN, "BN", blockNumber)
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
		log.Debug("HC will check randomCache for", "cNum", cNum, "key", thisKey)

		thisCE = hcs.GetRandom(thisKey)
		if thisCE == nil {
			log.Debug("HC Cache entry not found for", "key", thisKey)
			return nil, nil, errors.New("DoRandomSeq state not found")
		} else if blockNumber < thisCE.commitBN+commitDepth {
			log.Debug("HC Invalid block number for DoRandomSeq", "expected", thisCE.commitBN, "actual", blockNumber)
			return nil, nil, errors.New("DoRandomSeq invalid block number")
		} else {
			result.Xor(cNum, thisCE.secret)
		}
	}

	if doStore {
		log.Debug("HC DoRandomSeq storing cache entry", "key", nextKey, "ce", nextCE)
		hcs.PutRandom(nextKey, nextCE)
	}

	log.Debug("HC DoRandomSeq successful", "sNext", sNext, "result", result)
	return &sNext, &result, nil
}

// Called after an EVM run to look for a trigger event
func CheckTrigger(hc *HCContext, input []byte, ret []byte, err error) bool {
	if hc == nil || hc.State != HC_STATE_NONE {
		return false
	}
	// Check for a revert
	if err != ErrExecutionReverted {
		return false
	}
	// Check for an "Error(string)" selector + the expected trigger string
	if len(ret) >= 100 && bytes.Equal(ret[:4], []byte{0x08, 0xc3, 0x79, 0xa0}) {
		trigger := []byte("HC: Missing cache entry")
		if !bytes.Equal(ret[68:68+len(trigger)], trigger) {
			log.Debug("HC CheckTrigger reverted without trigger string", "ret", hexutility.Bytes(ret))
			return false
		}
	}
	// Check the selector for a recognized method
	msgSel := binary.BigEndian.Uint32(input[:4])
	switch msgSel {
	case HC_OP_LEGACY_RANDOM, HC_OP_LEGACY_OFFCHAIN, HC_OP_OFFCHAIN_V1, HC_OP_RANDSEQ_V1:
		hc.State = HC_STATE_TRIGGERED
		hc.OpType = msgSel
		log.Debug("HC Triggered", "sel", hexutility.Bytes(input[:4]))
	default:
		log.Debug("HC noTrigger", "sel", hexutility.Bytes(input[:4]))
		return false
	}
	return true
}

// Main function to process a Hybrid Compute request after it's triggered.
func HCRequest(hcs *HCService, hc *HCContext, blockNumber uint64) error {
	log.Debug("HC Request", "req", hexutility.Bytes(hc.Request))

	var (
		//tAddress,_ = abi.NewType("address", "", nil)
		tBytes, _   = abi.NewType("bytes", "", nil)
		tBytes32, _ = abi.NewType("bytes32", "", nil)
		tString, _  = abi.NewType("string", "", nil)
		tUint32, _  = abi.NewType("uint32", "", nil)
		tUint256, _ = abi.NewType("uint256", "", nil)
		tBool, _    = abi.NewType("bool", "", nil)
	)

	var reqKey libcommon.Hash
	var err error         // Errors within the sequencer
	var responseErr error // Errors returned to the caller
	var success bool
	var responseBytes []byte
	hasher := sha3.NewLegacyKeccak256()

	selBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(selBuf, hc.OpType)
	hasher.Write(selBuf)

	switch hc.OpType {
	case HC_OP_LEGACY_RANDOM:
		// SimpleRandom
		r256, err := HCGenerateRandom()
		if err != nil {
			log.Warn("HC LegacyRandom failed", "err", err)
			hc.State = HC_STATE_FAILED
			return ErrHCFailed
		}
		r32 := r256.Bytes32()
		responseBytes = r32[:]

		hasher.Write(hc.Caller.Bytes())
	case HC_OP_LEGACY_OFFCHAIN:
		dec, err := (abi.Arguments{{Type: tUint32}, {Type: tString}, {Type: tBytes}}).Unpack(hc.Request[4:])
		log.Debug("HC ABI decode (offchain)", "dec", dec, "err", err, "hc", hc)

		legacyVersion := dec[0].(uint32)
		log.Debug("HC Legacy Offchain call", "version", legacyVersion)

		if err != nil {
			log.Warn("HC Request decode failed", "err", err)
			hc.State = HC_STATE_FAILED
			return ErrHCFailed
		}
		reqUrl := dec[1].(string)
		reqMethod := hc.Caller
		reqPayload := dec[2].([]byte)

		hasher.Write(hc.Caller.Bytes())
		hasher.Write([]byte(reqUrl))
		hasher.Write(reqPayload)

		if legacyVersion == 1 {
			// Originally a Length field was prepended to the offchain request and response.
			pLen := uint32(len(reqPayload))
			prefix, err := (abi.Arguments{{Type: tUint32}}).Pack(pLen)
			if err != nil {
				log.Warn("HC Legacy-encode failed", "err", err)
				hc.State = HC_STATE_FAILED
				return ErrHCFailed
			}
			reqPayload = append(prefix, reqPayload...)
			log.Debug("HC legacyVersion new payload", "reqPayload", reqPayload)
		}

		log.Debug("HC Legacy Request", "reqUrl", reqUrl, "reqMethod", reqMethod)
		responseBytes, responseErr = DoOffchain(reqUrl, reqMethod, reqPayload)
		if responseErr != nil {
			log.Debug("HC LegacyOffchain failed", "responseErr", responseErr)
		}
		log.Debug("HC Legacy Request (1)", "responseErr", responseErr, "responseBytes", hexutility.Bytes(responseBytes))

		if legacyVersion == 1 {
			responseLen := new(big.Int).SetBytes(responseBytes[:32])
			responseBytes = responseBytes[32:]

			if responseLen.Cmp(big.NewInt(int64(len(responseBytes)))) != 0 {
				log.Warn("HC Legacy-decode length mismatch", "expected", responseLen, "actual", len(responseBytes))
				hc.State = HC_STATE_FAILED
				return ErrHCFailed
			}
		}
		log.Debug("HC Legacy Request (2)", "responseErr", responseErr, "responseBytes", hexutility.Bytes(responseBytes))
	case HC_OP_OFFCHAIN_V1:
		// We now expect to have an ABI-encoded (url_string, payload_bytes)
		dec, err := (abi.Arguments{{Type: tString}, {Type: tBytes}}).Unpack(hc.Request[4:])
		log.Debug("HC ABI decode (offchain)", "dec", dec, "err", err, "hc", hc)

		if err != nil {
			log.Warn("HC Request decode failed", "err", err)
			hc.State = HC_STATE_FAILED
			return ErrHCFailed
		}
		reqUrl := dec[0].(string)
		reqMethod := hc.Caller
		reqPayload := dec[1].([]byte)

		hasher.Write(hc.Caller.Bytes())
		hasher.Write([]byte(reqUrl))
		hasher.Write(reqPayload)

		log.Debug("HC Request", "reqUrl", reqUrl, "reqMethod", reqMethod)
		responseBytes, responseErr = DoOffchain(reqUrl, reqMethod, reqPayload)
		if responseErr != nil {
			log.Debug("HC DoOffchain failed", "responseErr", responseErr, "response", responseBytes)
		}
		log.Debug("HC Request", "responseErr", responseErr, "responseBytes", hexutility.Bytes(responseBytes))
	case HC_OP_RANDSEQ_V1:
		dec, err := (abi.Arguments{{Type: tBytes32}, {Type: tBytes32}, {Type: tUint256}}).Unpack(hc.Request[4:])
		if err != nil {
			log.Warn("HC Request decode failed", "err", err)
			hc.State = HC_STATE_FAILED
			return ErrHCFailed
		}
		log.Debug("HC ABI decode (randomseq)", "dec", dec, "err", err, "BN", blockNumber, "hc", hc)

		session := dec[0].([32]byte)
		chBytes := dec[1].([32]byte)
		clientHash := libcommon.BytesToHash(chBytes[:])
		var clientNum *uint256.Int
		clientNum = uint256.MustFromBig(dec[2].(*big.Int))

		log.Debug("HC ABI decode (randomseq)", "session", hexutility.Bytes(session[:]), "clientHash", clientHash, "clientNum", clientNum)

		hasher.Write(hc.Caller.Bytes())
		hasher.Write(session[:])
		hasher.Write(clientHash.Bytes())
		cTmp := clientNum.Bytes32()
		hasher.Write(cTmp[:])

		sNext, resultNum, err := DoRandomSeq(hcs, hc.Caller, session, clientHash, clientNum, blockNumber)

		if err == nil {
			xHash := *sNext
			xNum := resultNum.ToBig()
			responseBytes, err = (abi.Arguments{{Type: tBytes32}, {Type: tUint256}}).Pack([32]byte(xHash), xNum)
			log.Debug("HC RandomSeq encode", "sNext", xHash, "resultNum", xNum, "err", err, "responseBytes", responseBytes)
		} else {
			responseBytes = nil
			responseErr = HC_ERR_RNG_FAILURE
		}
		log.Debug("HC RandomSeq result", "err", err, "responseBytes", responseBytes)
	default:
		log.Debug("HC Unknown opType", "opType", hc.OpType)
		hc.State = HC_STATE_FAILED
		return ErrHCFailed
	}

	reqKey = libcommon.BytesToHash(hasher.Sum(nil))
	log.Debug("HC Request", "reqKey", reqKey)

	hc.Response = []byte{0xeb, 0x65, 0x98, 0xb5} // PutResponse(bytes32,bool,bytes)

	if responseErr == nil {
		success = true
	} else {
		responseBytes = []byte(responseErr.Error())
	}
	resp, err := (abi.Arguments{{Type: tBytes32}, {Type: tBool}, {Type: tBytes}}).Pack([32]byte(reqKey), success, responseBytes)

	if err != nil {
		log.Warn("HC Response encode failed", "err", err)
		hc.State = HC_STATE_FAILED
		return ErrHCFailed
	}

	hc.Response = append(hc.Response, resp...)
	log.Debug("HC Response", "hcData", hexutility.Bytes(hc.Response))

	hc.State = HC_STATE_READY
	return nil
}
