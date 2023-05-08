package main

import (
	"fmt"
	"math/big"

	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/rpc"
)

func main() {
	client, err := rpc.Dial("https://mainnet.boba.network")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer client.Close()
	var block types.Header

	err = client.Call(&block, "eth_getBlockByNumber", big.NewInt(10000000), false)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Block: %v\n", block.Number)
	return
}
