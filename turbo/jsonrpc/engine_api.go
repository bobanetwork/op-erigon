package jsonrpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/log/v3"

	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/hexutility"
	"github.com/ledgerwatch/erigon-lib/gointerfaces"
	"github.com/ledgerwatch/erigon-lib/gointerfaces/engine"
	types2 "github.com/ledgerwatch/erigon-lib/gointerfaces/types"
	"github.com/ledgerwatch/erigon-lib/kv"

	"github.com/ledgerwatch/erigon/common/hexutil"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/rpc"
	"github.com/ledgerwatch/erigon/turbo/engineapi"
	"github.com/ledgerwatch/erigon/turbo/engineapi/engine_helpers"
	"github.com/ledgerwatch/erigon/turbo/rpchelper"
)

// ExecutionPayload represents an execution payload (aka block)
type ExecutionPayload struct {
	ParentHash    common.Hash         `json:"parentHash"    gencodec:"required"`
	FeeRecipient  common.Address      `json:"feeRecipient"  gencodec:"required"`
	StateRoot     common.Hash         `json:"stateRoot"     gencodec:"required"`
	ReceiptsRoot  common.Hash         `json:"receiptsRoot"  gencodec:"required"`
	LogsBloom     hexutility.Bytes    `json:"logsBloom"     gencodec:"required"`
	PrevRandao    common.Hash         `json:"prevRandao"    gencodec:"required"`
	BlockNumber   hexutil.Uint64      `json:"blockNumber"   gencodec:"required"`
	GasLimit      hexutil.Uint64      `json:"gasLimit"      gencodec:"required"`
	GasUsed       hexutil.Uint64      `json:"gasUsed"       gencodec:"required"`
	Timestamp     hexutil.Uint64      `json:"timestamp"     gencodec:"required"`
	ExtraData     hexutility.Bytes    `json:"extraData"     gencodec:"required"`
	BaseFeePerGas *hexutil.Big        `json:"baseFeePerGas" gencodec:"required"`
	BlockHash     common.Hash         `json:"blockHash"     gencodec:"required"`
	Transactions  []hexutility.Bytes  `json:"transactions"  gencodec:"required"`
	Withdrawals   []*types.Withdrawal `json:"withdrawals"`
	DataGasUsed   *hexutil.Uint64     `json:"dataGasUsed"`
	ExcessDataGas *hexutil.Uint64     `json:"excessDataGas"`
}

// GetPayloadV2Response represents the response of the getPayloadV2 method
type GetPayloadV2Response struct {
	ExecutionPayload *ExecutionPayload `json:"executionPayload" gencodec:"required"`
	BlockValue       *hexutil.Big      `json:"blockValue" gencodec:"required"`
}

// GetPayloadV3Response represents the response of the getPayloadV3 method
type GetPayloadV3Response struct {
	ExecutionPayload *ExecutionPayload `json:"executionPayload" gencodec:"required"`
	BlockValue       *hexutil.Big      `json:"blockValue"       gencodec:"required"`
	BlobsBundle      *BlobsBundleV1    `json:"blobsBundle"      gencodec:"required"`
}

// PayloadAttributes represent the attributes required to start assembling a payload
type ForkChoiceState struct {
	HeadHash           common.Hash `json:"headBlockHash"             gencodec:"required"`
	SafeBlockHash      common.Hash `json:"safeBlockHash"             gencodec:"required"`
	FinalizedBlockHash common.Hash `json:"finalizedBlockHash"        gencodec:"required"`
}

// PayloadAttributes represent the attributes required to start assembling a payload
type PayloadAttributes struct {
	Timestamp             hexutil.Uint64      `json:"timestamp"             gencodec:"required"`
	PrevRandao            common.Hash         `json:"prevRandao"            gencodec:"required"`
	SuggestedFeeRecipient common.Address      `json:"suggestedFeeRecipient" gencodec:"required"`
	Withdrawals           []*types.Withdrawal `json:"withdrawals"           gencodec:"optional"`
	Transactions          []hexutility.Bytes  `json:"transactions"          gencodec:"optional"`
	NoTxPool              bool                `json:"noTxPool"              gencodec:"optional"`
	GasLimit              *hexutil.Uint64     `json:"gasLimit"              gencodec:"optional"`
}

// TransitionConfiguration represents the correct configurations of the CL and the EL
type TransitionConfiguration struct {
	TerminalTotalDifficulty *hexutil.Big `json:"terminalTotalDifficulty" gencodec:"required"`
	TerminalBlockHash       common.Hash  `json:"terminalBlockHash"       gencodec:"required"`
	TerminalBlockNumber     *hexutil.Big `json:"terminalBlockNumber"     gencodec:"required"`
}

// BlobsBundleV1 holds the blobs of an execution payload
type BlobsBundleV1 struct {
	Commitments []types.KZGCommitment `json:"commitments" gencodec:"required"`
	Proofs      []types.KZGProof      `json:"proofs"      gencodec:"required"`
	Blobs       []types.Blob          `json:"blobs"       gencodec:"required"`
}

type ExecutionPayloadBodyV1 struct {
	Transactions []hexutility.Bytes  `json:"transactions" gencodec:"required"`
	Withdrawals  []*types.Withdrawal `json:"withdrawals"  gencodec:"required"`
}

// EngineAPI Beacon chain communication endpoint
type EngineAPI interface {
	NewPayloadV1(context.Context, *ExecutionPayload) (map[string]interface{}, error)
	NewPayloadV2(context.Context, *ExecutionPayload) (map[string]interface{}, error)
	NewPayloadV3(context.Context, *ExecutionPayload) (map[string]interface{}, error)
	ForkchoiceUpdatedV1(ctx context.Context, forkChoiceState *ForkChoiceState, payloadAttributes *PayloadAttributes) (map[string]interface{}, error)
	ForkchoiceUpdatedV2(ctx context.Context, forkChoiceState *ForkChoiceState, payloadAttributes *PayloadAttributes) (map[string]interface{}, error)
	GetPayloadV1(ctx context.Context, payloadID hexutility.Bytes) (*ExecutionPayload, error)
	GetPayloadV2(ctx context.Context, payloadID hexutility.Bytes) (*GetPayloadV2Response, error)
	GetPayloadV3(ctx context.Context, payloadID hexutility.Bytes) (*GetPayloadV3Response, error)
	ExchangeTransitionConfigurationV1(ctx context.Context, transitionConfiguration *TransitionConfiguration) (*TransitionConfiguration, error)
	GetPayloadBodiesByHashV1(ctx context.Context, hashes []common.Hash) ([]*ExecutionPayloadBodyV1, error)
	GetPayloadBodiesByRangeV1(ctx context.Context, start, count hexutil.Uint64) ([]*ExecutionPayloadBodyV1, error)
}

// EngineImpl is implementation of the EngineAPI interface
type EngineImpl struct {
	*BaseAPI
	db  kv.RoDB
	api rpchelper.EngineBackend
}

func convertPayloadStatus(ctx context.Context, db kv.RoDB, x *engine.EnginePayloadStatus) (map[string]interface{}, error) {
	json := map[string]interface{}{
		"status": x.Status.String(),
	}
	if x.ValidationError != "" {
		json["validationError"] = x.ValidationError
	}
	if x.LatestValidHash == nil || (x.Status != engine.EngineStatus_VALID && x.Status != engine.EngineStatus_INVALID) {
		return json, nil
	}

	latestValidHash := common.Hash(gointerfaces.ConvertH256ToHash(x.LatestValidHash))
	if latestValidHash == (common.Hash{}) || x.Status == engine.EngineStatus_VALID {
		json["latestValidHash"] = latestValidHash
		return json, nil
	}

	// Per the Engine API spec latestValidHash should be set to 0x0000000000000000000000000000000000000000000000000000000000000000
	// if it refers to a PoW block.
	tx, err := db.BeginRo(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	isValidHashPos, err := rawdb.IsPosBlock(tx, latestValidHash)
	if err != nil {
		return nil, err
	}

	if isValidHashPos {
		json["latestValidHash"] = latestValidHash
	} else {
		json["latestValidHash"] = common.Hash{}
	}
	return json, nil
}

// Engine API specifies that payloadId is 8 bytes
func addPayloadId(json map[string]interface{}, payloadId uint64) {
	if payloadId != 0 {
		encodedPayloadId := make([]byte, 8)
		binary.BigEndian.PutUint64(encodedPayloadId, payloadId)
		json["payloadId"] = hexutility.Bytes(encodedPayloadId)
	}
}

func (e *EngineImpl) ForkchoiceUpdatedV1(ctx context.Context, forkChoiceState *ForkChoiceState, payloadAttributes *PayloadAttributes) (map[string]interface{}, error) {
	return e.forkchoiceUpdated(1, ctx, forkChoiceState, payloadAttributes)
}

func (e *EngineImpl) ForkchoiceUpdatedV2(ctx context.Context, forkChoiceState *ForkChoiceState, payloadAttributes *PayloadAttributes) (map[string]interface{}, error) {
	return e.forkchoiceUpdated(2, ctx, forkChoiceState, payloadAttributes)
}

// Converts slice of pointers to slice of structs
func withdrawalValues(ptrs []*types.Withdrawal) []types.Withdrawal {
	if ptrs == nil {
		return nil
	}
	vals := make([]types.Withdrawal, 0, len(ptrs))
	for _, w := range ptrs {
		vals = append(vals, *w)
	}
	return vals
}

var errEmbedeedConsensus = errors.New("engine api should not be used, restart without --internalcl")

func (e *EngineImpl) forkchoiceUpdated(version uint32, ctx context.Context, forkChoiceState *ForkChoiceState, payloadAttributes *PayloadAttributes) (map[string]interface{}, error) {

	if payloadAttributes == nil {
		log.Debug("Received ForkchoiceUpdated", "version", version,
			"head", forkChoiceState.HeadHash, "safe", forkChoiceState.SafeBlockHash, "finalized", forkChoiceState.FinalizedBlockHash)
	} else {
		log.Info("Received ForkchoiceUpdated [build]", "version", version,
			"head", forkChoiceState.HeadHash, "safe", forkChoiceState.SafeBlockHash, "finalized", forkChoiceState.FinalizedBlockHash,
			"timestamp", payloadAttributes.Timestamp, "prevRandao", payloadAttributes.PrevRandao, "suggestedFeeRecipient", payloadAttributes.SuggestedFeeRecipient,
			"withdrawals", withdrawalValues(payloadAttributes.Withdrawals),
			"numTransactions", len(payloadAttributes.Transactions),
			"gasLimit", (*uint64)(payloadAttributes.GasLimit), "NoTxPool", payloadAttributes.NoTxPool)
	}

	var attributes *engine.EnginePayloadAttributes
	if payloadAttributes != nil {
		// Could move this to erigon-lib/gointerfaces/type_utils.go but there's a problem
		// importing hexutils into erigon-lib.
		transactions := make([][]byte, len(payloadAttributes.Transactions))
		for i, transaction := range payloadAttributes.Transactions {
			transactions[i] = ([]byte)(transaction)
		}
		attributes = &engine.EnginePayloadAttributes{
			Version:               1,
			Timestamp:             uint64(payloadAttributes.Timestamp),
			PrevRandao:            gointerfaces.ConvertHashToH256(payloadAttributes.PrevRandao),
			SuggestedFeeRecipient: gointerfaces.ConvertAddressToH160(payloadAttributes.SuggestedFeeRecipient),
			Transactions:          transactions,
			NoTxPool:              payloadAttributes.NoTxPool,
			GasLimit:              (*uint64)(payloadAttributes.GasLimit),
		}
		if version >= 2 && payloadAttributes.Withdrawals != nil {
			attributes.Version = 2
			attributes.Withdrawals = engineapi.ConvertWithdrawalsToRpc(payloadAttributes.Withdrawals)
		}
	}
	reply, err := e.api.EngineForkchoiceUpdated(ctx, &engine.EngineForkChoiceUpdatedRequest{
		ForkchoiceState: &engine.EngineForkChoiceState{
			HeadBlockHash:      gointerfaces.ConvertHashToH256(forkChoiceState.HeadHash),
			SafeBlockHash:      gointerfaces.ConvertHashToH256(forkChoiceState.SafeBlockHash),
			FinalizedBlockHash: gointerfaces.ConvertHashToH256(forkChoiceState.FinalizedBlockHash),
		},
		PayloadAttributes: attributes,
	})
	if err != nil {
		return nil, err
	}

	payloadStatus, err := convertPayloadStatus(ctx, e.db, reply.PayloadStatus)
	if err != nil {
		return nil, err
	}

	json := map[string]interface{}{
		"payloadStatus": payloadStatus,
	}

	if reply.PayloadId != 0 {
		encodedPayloadId := make([]byte, 8)
		binary.BigEndian.PutUint64(encodedPayloadId, reply.PayloadId)
		json["payloadId"] = hexutility.Bytes(encodedPayloadId)
	}
	log.Debug("Sending ForkchoiceUpdatedV1 Response", "json", json)
	addPayloadId(json, reply.PayloadId)

	return json, nil
}

// NewPayloadV1 processes new payloads (blocks) from the beacon chain without withdrawals.

// See https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#engine_newpayloadv1
func (e *EngineImpl) NewPayloadV1(ctx context.Context, payload *ExecutionPayload) (map[string]interface{}, error) {
	return e.newPayload(1, ctx, payload)
}

// NewPayloadV2 processes new payloads (blocks) from the beacon chain with withdrawals.
// See https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#engine_newpayloadv2
func (e *EngineImpl) NewPayloadV2(ctx context.Context, payload *ExecutionPayload) (map[string]interface{}, error) {
	return e.newPayload(2, ctx, payload)
}

// NewPayloadV3 processes new payloads (blocks) from the beacon chain with withdrawals & excess data gas.
// See https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_newpayloadv3
func (e *EngineImpl) NewPayloadV3(ctx context.Context, payload *ExecutionPayload) (map[string]interface{}, error) {
	return e.newPayload(3, ctx, payload)
}

func (e *EngineImpl) newPayload(version uint32, ctx context.Context, payload *ExecutionPayload) (map[string]interface{}, error) {
	log.Debug("Received NewPayload", "version", version, "height", uint64(payload.BlockNumber), "hash", payload.BlockHash)

	baseFee, overflow := uint256.FromBig((*big.Int)(payload.BaseFeePerGas))
	if overflow {
		log.Warn("NewPayload BaseFeePerGas overflow")
		return nil, fmt.Errorf("invalid request")
	}

	// Convert slice of hexutility.Bytes to a slice of slice of bytes
	transactions := make([][]byte, len(payload.Transactions))
	for i, transaction := range payload.Transactions {
		transactions[i] = transaction
	}
	ep := &types2.ExecutionPayload{
		Version:       1,
		ParentHash:    gointerfaces.ConvertHashToH256(payload.ParentHash),
		Coinbase:      gointerfaces.ConvertAddressToH160(payload.FeeRecipient),
		StateRoot:     gointerfaces.ConvertHashToH256(payload.StateRoot),
		ReceiptRoot:   gointerfaces.ConvertHashToH256(payload.ReceiptsRoot),
		LogsBloom:     gointerfaces.ConvertBytesToH2048(payload.LogsBloom),
		PrevRandao:    gointerfaces.ConvertHashToH256(payload.PrevRandao),
		BlockNumber:   uint64(payload.BlockNumber),
		GasLimit:      uint64(payload.GasLimit),
		GasUsed:       uint64(payload.GasUsed),
		Timestamp:     uint64(payload.Timestamp),
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: gointerfaces.ConvertUint256IntToH256(baseFee),
		BlockHash:     gointerfaces.ConvertHashToH256(payload.BlockHash),
		Transactions:  transactions,
	}
	if version >= 2 && payload.Withdrawals != nil {
		ep.Version = 2
		ep.Withdrawals = engineapi.ConvertWithdrawalsToRpc(payload.Withdrawals)
	}
	if version >= 3 && payload.DataGasUsed != nil && payload.ExcessDataGas != nil {
		ep.Version = 3
		dataGasUsed := uint64(*payload.DataGasUsed)
		ep.DataGasUsed = &dataGasUsed
		excessDataGas := uint64(*payload.ExcessDataGas)
		ep.ExcessDataGas = &excessDataGas
	}

	res, err := e.api.EngineNewPayload(ctx, ep)
	if err != nil {
		log.Warn("NewPayload", "err", err)
		return nil, err
	}
	log.Debug("Returning NewPayload Response", "BN", uint64(payload.BlockNumber), "res", res)
	return convertPayloadStatus(ctx, e.db, res)
}

func convertPayloadFromRpc(payload *types2.ExecutionPayload) *ExecutionPayload {
	var bloom types.Bloom = gointerfaces.ConvertH2048ToBloom(payload.LogsBloom)
	baseFee := gointerfaces.ConvertH256ToUint256Int(payload.BaseFeePerGas).ToBig()

	// Convert slice of hexutility.Bytes to a slice of slice of bytes
	transactions := make([]hexutility.Bytes, len(payload.Transactions))
	for i, transaction := range payload.Transactions {
		transactions[i] = transaction
	}

	log.Debug("Building convertPayloadFromRpc response", "payload", payload, "numTransactions", len(transactions))
	res := &ExecutionPayload{
		ParentHash:    gointerfaces.ConvertH256ToHash(payload.ParentHash),
		FeeRecipient:  gointerfaces.ConvertH160toAddress(payload.Coinbase),
		StateRoot:     gointerfaces.ConvertH256ToHash(payload.StateRoot),
		ReceiptsRoot:  gointerfaces.ConvertH256ToHash(payload.ReceiptRoot),
		LogsBloom:     bloom[:],
		PrevRandao:    gointerfaces.ConvertH256ToHash(payload.PrevRandao),
		BlockNumber:   hexutil.Uint64(payload.BlockNumber),
		GasLimit:      hexutil.Uint64(payload.GasLimit),
		GasUsed:       hexutil.Uint64(payload.GasUsed),
		Timestamp:     hexutil.Uint64(payload.Timestamp),
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: (*hexutil.Big)(baseFee),
		BlockHash:     gointerfaces.ConvertH256ToHash(payload.BlockHash),
		Transactions:  transactions,
	}
	if payload.Version >= 2 {
		res.Withdrawals = engineapi.ConvertWithdrawalsFromRpc(payload.Withdrawals)
	}
	if payload.Version >= 3 {
		dataGasUsed := *payload.DataGasUsed
		res.DataGasUsed = (*hexutil.Uint64)(&dataGasUsed)
		excessDataGas := *payload.ExcessDataGas
		res.ExcessDataGas = (*hexutil.Uint64)(&excessDataGas)
	}
	return res
}

func (e *EngineImpl) GetPayloadV1(ctx context.Context, payloadID hexutility.Bytes) (*ExecutionPayload, error) {
	decodedPayloadId := binary.BigEndian.Uint64(payloadID)
	log.Info("Received GetPayloadV1", "payloadId", decodedPayloadId)

	response, err := e.api.EngineGetPayload(ctx, decodedPayloadId)
	if err != nil {
		return nil, err
	}

	return convertPayloadFromRpc(response.ExecutionPayload), nil
}

func (e *EngineImpl) GetPayloadV2(ctx context.Context, payloadID hexutility.Bytes) (*GetPayloadV2Response, error) {
	decodedPayloadId := binary.BigEndian.Uint64(payloadID)
	log.Info("Received GetPayloadV2", "payloadId", decodedPayloadId)

	response, err := e.api.EngineGetPayload(ctx, decodedPayloadId)
	if err != nil {
		return nil, err
	}

	epl := convertPayloadFromRpc(response.ExecutionPayload)
	blockValue := gointerfaces.ConvertH256ToUint256Int(response.BlockValue).ToBig()
	return &GetPayloadV2Response{
		epl,
		(*hexutil.Big)(blockValue),
	}, nil
}

func (e *EngineImpl) GetPayloadV3(ctx context.Context, payloadID hexutility.Bytes) (*GetPayloadV3Response, error) {
	decodedPayloadId := binary.BigEndian.Uint64(payloadID)
	log.Info("Received GetPayloadV3", "payloadId", decodedPayloadId)

	response, err := e.api.EngineGetPayload(ctx, decodedPayloadId)
	if err != nil {
		return nil, err
	}

	epl := convertPayloadFromRpc(response.ExecutionPayload)
	blockValue := gointerfaces.ConvertH256ToUint256Int(response.BlockValue).ToBig()

	commitments := response.BlobsBundle.GetCommitments()
	proofs := response.BlobsBundle.GetProofs()
	blobs := response.BlobsBundle.GetBlobs()
	if len(commitments) != len(proofs) || len(proofs) != len(blobs) {
		return nil, fmt.Errorf("should have same number of commitments/proofs/blobs, got %v vs %v vs %v", len(commitments), len(proofs), len(blobs))
	}
	replyCommitments := make([]types.KZGCommitment, len(commitments))
	replyProofs := make([]types.KZGProof, len(proofs))
	replyBlobs := make([]types.Blob, len(blobs))
	for i := range commitments {
		copy(replyCommitments[i][:], commitments[i])
		copy(replyProofs[i][:], proofs[i])
		copy(replyBlobs[i][:], blobs[i])
	}
	bb := &BlobsBundleV1{
		Commitments: replyCommitments,
		Proofs:      replyProofs,
		Blobs:       replyBlobs,
	}

	return &GetPayloadV3Response{
		epl,
		(*hexutil.Big)(blockValue),
		bb,
	}, nil
}

// Receives consensus layer's transition configuration and checks if the execution layer has the correct configuration.
// Can also be used to ping the execution layer (heartbeats).
// See https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.1/src/engine/specification.md#engine_exchangetransitionconfigurationv1
func (e *EngineImpl) ExchangeTransitionConfigurationV1(ctx context.Context, beaconConfig *TransitionConfiguration) (*TransitionConfiguration, error) {
	tx, err := e.db.BeginRo(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	chainConfig, err := e.BaseAPI.chainConfig(tx)
	if err != nil {
		return nil, err
	}

	terminalTotalDifficulty := chainConfig.TerminalTotalDifficulty

	if terminalTotalDifficulty == nil {
		return nil, fmt.Errorf("the execution layer doesn't have a terminal total difficulty. expected: %v", beaconConfig.TerminalTotalDifficulty)
	}

	if terminalTotalDifficulty.Cmp((*big.Int)(beaconConfig.TerminalTotalDifficulty)) != 0 {
		return nil, fmt.Errorf("the execution layer has a wrong terminal total difficulty. expected %v, but instead got: %d", beaconConfig.TerminalTotalDifficulty, terminalTotalDifficulty)
	}

	return &TransitionConfiguration{
		TerminalTotalDifficulty: (*hexutil.Big)(terminalTotalDifficulty),
		TerminalBlockHash:       common.Hash{},
		TerminalBlockNumber:     (*hexutil.Big)(common.Big0),
	}, nil
}

func (e *EngineImpl) GetPayloadBodiesByHashV1(ctx context.Context, hashes []common.Hash) ([]*ExecutionPayloadBodyV1, error) {
	if len(hashes) > 1024 {
		return nil, &engine_helpers.TooLargeRequestErr
	}

	h := make([]*types2.H256, len(hashes))
	for i, hash := range hashes {
		h[i] = gointerfaces.ConvertHashToH256(hash)
	}

	apiRes, err := e.api.EngineGetPayloadBodiesByHashV1(ctx, &engine.EngineGetPayloadBodiesByHashV1Request{Hashes: h})
	if err != nil {
		return nil, err
	}

	return convertExecutionPayloadV1(apiRes), nil
}

func (e *EngineImpl) GetPayloadBodiesByRangeV1(ctx context.Context, start, count hexutil.Uint64) ([]*ExecutionPayloadBodyV1, error) {
	if start == 0 || count == 0 {
		return nil, &rpc.InvalidParamsError{Message: fmt.Sprintf("invalid start or count, start: %v count: %v", start, count)}
	}
	if count > 1024 {
		return nil, &engine_helpers.TooLargeRequestErr
	}

	apiRes, err := e.api.EngineGetPayloadBodiesByRangeV1(ctx, &engine.EngineGetPayloadBodiesByRangeV1Request{Start: uint64(start), Count: uint64(count)})
	if err != nil {
		return nil, err
	}

	return convertExecutionPayloadV1(apiRes), nil
}

var ourCapabilities = []string{
	"engine_forkchoiceUpdatedV1",
	"engine_forkchoiceUpdatedV2",
	"engine_newPayloadV1",
	"engine_newPayloadV2",
	// "engine_newPayloadV3",
	"engine_getPayloadV1",
	"engine_getPayloadV2",
	// "engine_getPayloadV3",
	"engine_exchangeTransitionConfigurationV1",
	"engine_getPayloadBodiesByHashV1",
	"engine_getPayloadBodiesByRangeV1",
}

func (e *EngineImpl) ExchangeCapabilities(fromCl []string) []string {
	missingOurs := compareCapabilities(fromCl, ourCapabilities)
	missingCl := compareCapabilities(ourCapabilities, fromCl)

	if len(missingCl) > 0 || len(missingOurs) > 0 {
		log.Debug("ExchangeCapabilities mismatches", "cl_unsupported", missingCl, "erigon_unsupported", missingOurs)
	}

	return ourCapabilities
}

func compareCapabilities(from []string, to []string) []string {
	result := make([]string, 0)
	for _, f := range from {
		found := false
		for _, t := range to {
			if f == t {
				found = true
				break
			}
		}
		if !found {
			result = append(result, f)
		}
	}

	return result
}

func convertExecutionPayloadV1(response *engine.EngineGetPayloadBodiesV1Response) []*ExecutionPayloadBodyV1 {
	result := make([]*ExecutionPayloadBodyV1, len(response.Bodies))
	for idx, body := range response.Bodies {
		if body == nil {
			result[idx] = nil
		} else {
			pl := &ExecutionPayloadBodyV1{
				Transactions: make([]hexutility.Bytes, len(body.Transactions)),
				Withdrawals:  engineapi.ConvertWithdrawalsFromRpc(body.Withdrawals),
			}
			for i := range body.Transactions {
				pl.Transactions[i] = body.Transactions[i]
			}
			result[idx] = pl
		}
	}

	return result
}

// NewEngineAPI returns EngineImpl instance
func NewEngineAPI(base *BaseAPI, db kv.RoDB, api rpchelper.EngineBackend) *EngineImpl {
	return &EngineImpl{
		BaseAPI: base,
		db:      db,
		api:     api,
	}
}