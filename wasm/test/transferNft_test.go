package test

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTransferNftSegmentFormat(t *testing.T) {

	var segmentFormat *txtypes.TransferNftSegmentFormat
	segmentFormat = &txtypes.TransferNftSegmentFormat{
		FromAccountIndex:  0,
		ToAccountIndex:    1,
		ToAccountNameHash: "ddc6171f9fe33153d95c8394c9135c277eb645401b85eb499393a2aefe6422a6",
		NftIndex:          15,
		GasAccountIndex:   1,
		GasFeeAssetId:     3,
		GasFeeAssetAmount: "3",
		CallData:          "",
		ExpiredAt:         1654656781000, // milli seconds
		Nonce:             1,
	}

	res, err := json.Marshal(segmentFormat)
	assert.Nil(t, err)

	log.Println(string(res))
}