/*
 * Copyright © 2022 ZkBNB Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package txtypes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/pkg/errors"
)

type AtomicMatchSegmentFormat struct {
	Offer string `json:"offer"`
	// OfferTxInfo Type

	AccountIndex int64  `json:"account_index"`
	Type         int64  `json:"type"`
	OfferId      int64  `json:"offer_id"`
	NftIndex     int64  `json:"nft_index"`
	AssetId      int64  `json:"asset_id"`
	AssetAmount  string `json:"asset_amount"`
	TreasuryRate int64  `json:"treasury_rate"`

	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	Nonce             int64  `json:"nonce"`
	// transaction amount +1 for fromAccountIndex
	ExpiredAt int64 `json:"expired_at"`
	// transaction expire time in milli-second type
	// eg. current timestamp + 1 week
}

/*
ConstructMintNftTxInfo: construct mint nft tx, sign txInfo
*/
func ConstructAtomicMatchTxInfo(sk *PrivateKey, segmentStr string) (txInfo *AtomicMatchTxInfo, err error) {
	var segmentFormat *AtomicMatchSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructAtomicMatchTxInfo] err info:", err)
		return nil, err
	}
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructAtomicMatchTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedFee(gasFeeAmount)
	var offer *OfferTxInfo
	err = json.Unmarshal([]byte(segmentFormat.Offer), &offer)
	if err != nil {
		log.Println("[ConstructAtomicMatchTxInfo] unable to unmarshal offer", err.Error())
		return nil, err
	}
	assetAmount, err := StringToBigInt(segmentFormat.AssetAmount)
	if err != nil {
		log.Println("[ConstructAtomicMatchTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetAmount, _ = CleanPackedAmount(assetAmount)
	txInfo = &AtomicMatchTxInfo{
		Offer:             offer,
		AccountIndex:      segmentFormat.AccountIndex,
		Type:              segmentFormat.Type,
		OfferId:           segmentFormat.OfferId,
		NftIndex:          segmentFormat.NftIndex,
		AssetId:           segmentFormat.AssetId,
		AssetAmount:       assetAmount,
		TreasuryRate:      segmentFormat.TreasuryRate,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		Nonce:             segmentFormat.Nonce,
		ExpiredAt:         segmentFormat.ExpiredAt,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash, err := txInfo.Hash(hFunc)
	if err != nil {
		log.Println("[ConstructAtomicMatchTxInfo] unable to compute hash: ", err.Error())
		return nil, err
	}
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructAtomicMatchTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type AtomicMatchTxInfo struct {
	// original offer
	Offer *OfferTxInfo

	// counterpart offer
	AccountIndex int64
	Type         int64
	OfferId      int64
	NftIndex     int64
	AssetId      int64
	AssetAmount  *big.Int
	TreasuryRate int64

	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	CreatorAmount     *big.Int
	TreasuryAmount    *big.Int
	Nonce             int64
	ExpiredAt         int64
	Sig               []byte
}

func (txInfo *AtomicMatchTxInfo) Validate() error {
	// AccountIndex
	if txInfo.AccountIndex < minAccountIndex {
		return ErrAccountIndexTooLow
	}
	if txInfo.AccountIndex > maxAccountIndex {
		return ErrAccountIndexTooHigh
	}

	// Offer
	if txInfo.Offer == nil {
		return ErrOfferInvalid
	}
	if err := txInfo.Offer.Validate(); err != nil {
		return errors.Wrap(ErrOfferInvalid, err.Error())
	}

	// Counterpart Offer
	offer := OfferTxInfo{
		Type:         txInfo.Type,
		OfferId:      txInfo.OfferId,
		AccountIndex: txInfo.AccountIndex,
		NftIndex:     txInfo.NftIndex,
		AssetId:      txInfo.AssetId,
		AssetAmount:  txInfo.AssetAmount,
		ListedAt:     txInfo.Offer.ListedAt,
		ExpiredAt:    txInfo.ExpiredAt,
		TreasuryRate: txInfo.TreasuryRate,
	}

	if err := offer.Validate(); err != nil {
		return err
	}

	if txInfo.Type == txInfo.Offer.Type {
		return ErrOfferTypeInvalid
	}

	// GasAccountIndex
	if txInfo.GasAccountIndex < minAccountIndex {
		return ErrGasAccountIndexTooLow
	}
	if txInfo.GasAccountIndex > maxAccountIndex {
		return ErrGasAccountIndexTooHigh
	}

	// GasFeeAssetId
	if txInfo.GasFeeAssetId < minAssetId {
		return ErrGasFeeAssetIdTooLow
	}
	if txInfo.GasFeeAssetId > maxAssetId {
		return ErrGasFeeAssetIdTooHigh
	}

	// GasFeeAssetAmount
	if txInfo.GasFeeAssetAmount == nil {
		return fmt.Errorf("GasFeeAssetAmount should not be nil")
	}
	if txInfo.GasFeeAssetAmount.Cmp(minPackedFeeAmount) < 0 {
		return ErrGasFeeAssetAmountTooLow
	}
	if txInfo.GasFeeAssetAmount.Cmp(maxPackedFeeAmount) > 0 {
		return ErrGasFeeAssetAmountTooHigh
	}

	// Nonce
	if txInfo.Nonce < minNonce {
		return ErrNonceTooLow
	}

	return nil
}

func (txInfo *AtomicMatchTxInfo) VerifySignature(pubKey string) error {
	// compute hash
	hFunc := mimc.NewMiMC()
	msgHash, err := txInfo.Hash(hFunc)
	if err != nil {
		return err
	}
	// verify signature
	hFunc.Reset()
	pk, err := ParsePublicKey(pubKey)
	if err != nil {
		return err
	}
	isValid, err := pk.Verify(txInfo.Sig, msgHash, hFunc)
	if err != nil {
		return err
	}

	if !isValid {
		return errors.New("invalid signature")
	}

	return nil
}

func (txInfo *AtomicMatchTxInfo) GetTxType() int {
	return TxTypeAtomicMatch
}

func (txInfo *AtomicMatchTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *AtomicMatchTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *AtomicMatchTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func (txInfo *AtomicMatchTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	hFunc.Reset()
	var buf bytes.Buffer
	packedOfferAmount, err := ToPackedAmount(txInfo.Offer.AssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	packedCounterpartAmount, err := ToPackedAmount(txInfo.AssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	WriteInt64IntoBuf(&buf, ChainId, txInfo.AccountIndex, txInfo.Nonce, txInfo.ExpiredAt)
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex, txInfo.GasFeeAssetId, packedFee)
	WriteInt64IntoBuf(&buf, txInfo.Offer.Type, txInfo.Offer.OfferId, txInfo.Offer.AccountIndex, txInfo.Offer.NftIndex)
	WriteInt64IntoBuf(&buf, txInfo.Offer.AssetId, packedOfferAmount, txInfo.Offer.ListedAt, txInfo.Offer.ExpiredAt)
	var offerSig = new(eddsa.Signature)
	_, err = offerSig.SetBytes(txInfo.Offer.Sig)
	if err != nil {
		log.Println("[ComputeAtomicMatchMsgHash] unable to convert to sig: ", err.Error())
		return nil, err
	}
	buf.Write(offerSig.R.X.Marshal())
	buf.Write(offerSig.R.Y.Marshal())
	buf.Write(offerSig.S[:])
	WriteInt64IntoBuf(&buf, txInfo.Type, txInfo.OfferId, txInfo.AccountIndex, txInfo.NftIndex)
	WriteInt64IntoBuf(&buf, txInfo.AssetId, packedCounterpartAmount, txInfo.ExpiredAt)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash, nil
}

func (txInfo *AtomicMatchTxInfo) GetGas() (int64, int64, *big.Int) {
	return txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount
}
