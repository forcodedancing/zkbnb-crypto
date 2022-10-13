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

package types

type AtomicMatchTx struct {
	Offer *OfferTx

	AccountIndex int64
	Type         int64
	OfferId      int64
	NftIndex     int64
	AssetId      int64
	AssetAmount  int64
	ExpiredAt    int64
	TreasuryRate int64

	CreatorAmount     int64
	TreasuryAmount    int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
}

type AtomicMatchTxConstraints struct {
	Offer OfferTxConstraints

	AccountIndex Variable
	Type         Variable
	OfferId      Variable
	NftIndex     Variable
	AssetId      Variable
	AssetAmount  Variable
	ExpiredAt    Variable

	TreasuryRate      Variable
	CreatorAmount     Variable
	TreasuryAmount    Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyAtomicMatchTxWitness() (witness AtomicMatchTxConstraints) {
	return AtomicMatchTxConstraints{
		Offer:             EmptyOfferTxWitness(),
		AccountIndex:      ZeroInt,
		Type:              ZeroInt,
		OfferId:           ZeroInt,
		NftIndex:          ZeroInt,
		AssetId:           ZeroInt,
		AssetAmount:       ZeroInt,
		ExpiredAt:         ZeroInt,
		CreatorAmount:     ZeroInt,
		TreasuryAmount:    ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func ComputeHashFromOfferTx(api API, tx OfferTxConstraints, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		PackInt64Variables(api, tx.Type, tx.OfferId, tx.AccountIndex, tx.NftIndex),
		PackInt64Variables(api, tx.AssetId, tx.AssetAmount, tx.ListedAt, tx.ExpiredAt),
		tx.TreasuryRate,
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func SetAtomicMatchTxWitness(tx *AtomicMatchTx) (witness AtomicMatchTxConstraints) {
	witness = AtomicMatchTxConstraints{
		Offer:             SetOfferTxWitness(tx.Offer),
		AccountIndex:      tx.AccountIndex,
		Type:              tx.Type,
		OfferId:           tx.OfferId,
		NftIndex:          tx.NftIndex,
		AssetId:           tx.AssetId,
		AssetAmount:       tx.AssetAmount,
		ExpiredAt:         tx.ExpiredAt,
		CreatorAmount:     tx.CreatorAmount,
		TreasuryAmount:    tx.TreasuryAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromAtomicMatchTx(api API, tx AtomicMatchTxConstraints, nonce Variable, expiredAt Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		PackInt64Variables(api, ChainId, tx.AccountIndex, nonce, expiredAt),
		PackInt64Variables(api, tx.GasAccountIndex, tx.GasFeeAssetId, tx.GasFeeAssetAmount),
		PackInt64Variables(api, tx.Offer.Type, tx.Offer.OfferId, tx.Offer.AccountIndex, tx.Offer.NftIndex),
		PackInt64Variables(api, tx.Offer.AssetId, tx.Offer.AssetAmount, tx.Offer.ListedAt, tx.Offer.ExpiredAt),
		tx.Offer.Sig.R.X,
		tx.Offer.Sig.R.Y,
		tx.Offer.Sig.S,
		PackInt64Variables(api, tx.Type, tx.OfferId, tx.AccountIndex, tx.NftIndex),
		PackInt64Variables(api, tx.AssetId, tx.AssetAmount, tx.ExpiredAt),
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func VerifyAtomicMatchTx(
	api API, flag Variable,
	tx *AtomicMatchTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
	blockCreatedAt Variable,
	hFunc MiMC,
) (pubData [PubDataSizePerTx]Variable, err error) {
	buyAccount := 0
	sellAccount := 1
	creatorAccount := 2

	pubData = CollectPubDataFromAtomicMatch(api, *tx)
	// verify params
	IsVariableEqual(api, flag, api.Add(tx.Offer.Type, tx.Type), 1)
	IsVariableEqual(api, flag, tx.Offer.AssetId, tx.AssetId)
	IsVariableEqual(api, flag, tx.Offer.AssetAmount, tx.AssetAmount)
	IsVariableEqual(api, flag, tx.Offer.NftIndex, tx.NftIndex)
	IsVariableEqual(api, flag, tx.Offer.AssetId, accountsBefore[buyAccount].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[sellAccount].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[creatorAccount].AssetsInfo[0].AssetId)
	//IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	IsVariableLessOrEqual(api, flag, blockCreatedAt, tx.Offer.ExpiredAt)
	IsVariableLessOrEqual(api, flag, blockCreatedAt, tx.ExpiredAt)
	IsVariableEqual(api, flag, nftBefore.NftIndex, tx.Offer.NftIndex)
	IsVariableEqual(api, flag, tx.Offer.TreasuryRate, tx.TreasuryRate)
	// verify signature
	hFunc.Reset()
	buyOfferHash := ComputeHashFromOfferTx(api, tx.Offer, hFunc)
	hFunc.Reset()
	notBuyer := api.IsZero(api.IsZero(api.Sub(tx.AccountIndex, tx.Offer.AccountIndex)))
	notBuyer = api.And(flag, notBuyer)
	err = VerifyEddsaSig(notBuyer, api, hFunc, buyOfferHash, accountsBefore[1].AccountPk, tx.Offer.Sig)
	if err != nil {
		return pubData, err
	}
	hFunc.Reset()
	sellOfferHash := ComputeHashFromOfferTx(api, tx.Offer, hFunc)
	hFunc.Reset()
	notSeller := api.IsZero(api.IsZero(api.Sub(tx.AccountIndex, tx.Offer.AccountIndex)))
	notSeller = api.And(flag, notSeller)
	err = VerifyEddsaSig(notSeller, api, hFunc, sellOfferHash, accountsBefore[2].AccountPk, tx.Offer.Sig)
	if err != nil {
		return pubData, err
	}
	// verify account index
	// submitter
	//IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[fromAccount].AccountIndex)
	// buyer
	IsVariableEqual(api, flag, tx.Offer.AccountIndex, accountsBefore[buyAccount].AccountIndex)
	// seller
	IsVariableEqual(api, flag, tx.Offer.AccountIndex, accountsBefore[sellAccount].AccountIndex)
	// creator
	IsVariableEqual(api, flag, nftBefore.CreatorAccountIndex, accountsBefore[creatorAccount].AccountIndex)
	// verify buy offer id
	buyOfferIdBits := api.ToBinary(tx.Offer.OfferId, 24)
	buyAssetId := api.FromBinary(buyOfferIdBits[7:]...)
	buyOfferIndex := api.Sub(tx.Offer.OfferId, api.Mul(buyAssetId, OfferSizePerAsset))
	buyOfferIndexBits := api.ToBinary(accountsBefore[buyAccount].AssetsInfo[1].OfferCanceledOrFinalized, OfferSizePerAsset)
	for i := 0; i < OfferSizePerAsset; i++ {
		isZero := api.IsZero(api.Sub(buyOfferIndex, i))
		IsVariableEqual(api, isZero, buyOfferIndexBits[i], 0)
	}
	// verify sell offer id
	sellOfferIdBits := api.ToBinary(tx.Offer.OfferId, 24)
	sellAssetId := api.FromBinary(sellOfferIdBits[7:]...)
	sellOfferIndex := api.Sub(tx.Offer.OfferId, api.Mul(sellAssetId, OfferSizePerAsset))
	sellOfferIndexBits := api.ToBinary(accountsBefore[sellAccount].AssetsInfo[1].OfferCanceledOrFinalized, OfferSizePerAsset)
	for i := 0; i < OfferSizePerAsset; i++ {
		isZero := api.IsZero(api.Sub(sellOfferIndex, i))
		IsVariableEqual(api, isZero, sellOfferIndexBits[i], 0)
	}
	// buyer should have enough balance
	tx.Offer.AssetAmount = UnpackAmount(api, tx.Offer.AssetAmount)
	IsVariableLessOrEqual(api, flag, tx.Offer.AssetAmount, accountsBefore[buyAccount].AssetsInfo[0].Balance)
	// submitter should have enough balance
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	//IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	return pubData, nil
}
