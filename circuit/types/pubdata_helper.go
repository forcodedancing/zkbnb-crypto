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

func CollectPubDataFromRegisterZNS(api API, txInfo RegisterZnsTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeRegisterZns, TxTypeBitsSize)
	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	ABits := append(accountIndexBits, txTypeBits...)
	var paddingSize [216]Variable
	for i := 0; i < 216; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = txInfo.AccountName
	pubData[2] = txInfo.AccountNameHash
	pubData[3] = txInfo.PubKey.A.X
	pubData[4] = txInfo.PubKey.A.Y
	for i := 5; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromDeposit(api API, txInfo DepositTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeDeposit, TxTypeBitsSize)
	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
	assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
	ABits := append(accountIndexBits, txTypeBits...)
	ABits = append(assetIdBits, ABits...)
	ABits = append(assetAmountBits, ABits...)
	var paddingSize [72]Variable
	for i := 0; i < 72; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = txInfo.AccountNameHash
	for i := 2; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromDepositNft(api API, txInfo DepositNftTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeDepositNft, TxTypeBitsSize)
	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
	nftL1AddressBits := api.ToBinary(txInfo.NftL1Address, AddressBitsSize)
	creatorAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
	creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize)
	collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
	ABits := append(accountIndexBits, txTypeBits...)
	ABits = append(nftIndexBits, ABits...)
	ABits = append(nftL1AddressBits, ABits...)
	var paddingSize [16]Variable
	for i := 0; i < 16; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	BBits := append(creatorTreasuryRateBits, creatorAccountIndexBits...)
	BBits = append(collectionIdBits, BBits...)
	pubData[1] = api.FromBinary(BBits...)
	pubData[2] = txInfo.NftContentHash
	pubData[3] = txInfo.NftL1TokenId
	pubData[4] = txInfo.AccountNameHash
	for i := 5; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromTransfer(api API, txInfo TransferTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeTransfer, TxTypeBitsSize)
	fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
	toAccountIndexBits := api.ToBinary(txInfo.ToAccountIndex, AccountIndexBitsSize)
	assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
	assetAmountBits := api.ToBinary(txInfo.AssetAmount, PackedAmountBitsSize)
	gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	ABits := append(fromAccountIndexBits, txTypeBits...)
	ABits = append(toAccountIndexBits, ABits...)
	ABits = append(assetIdBits, ABits...)
	ABits = append(assetAmountBits, ABits...)
	ABits = append(gasAccountIndexBits, ABits...)
	ABits = append(gasFeeAssetIdBits, ABits...)
	ABits = append(gasFeeAssetAmountBits, ABits...)
	var paddingSize [64]Variable
	for i := 0; i < 64; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = txInfo.CallDataHash
	for i := 2; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromWithdraw(api API, txInfo WithdrawTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeWithdraw, TxTypeBitsSize)
	fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
	toAddressBits := api.ToBinary(txInfo.ToAddress, AddressBitsSize)
	assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
	assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
	gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	ABits := append(fromAccountIndexBits, txTypeBits...)
	ABits = append(toAddressBits, ABits...)
	ABits = append(assetIdBits, ABits...)
	BBits := append(gasAccountIndexBits, assetAmountBits...)
	BBits = append(gasFeeAssetIdBits, BBits...)
	BBits = append(gasFeeAssetAmountBits, BBits...)
	var paddingSize [40]Variable
	for i := 0; i < 40; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = api.FromBinary(BBits...)
	for i := 2; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromCreateCollection(api API, txInfo CreateCollectionTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeCreateCollection, TxTypeBitsSize)
	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
	gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	ABits := append(accountIndexBits, txTypeBits...)
	ABits = append(collectionIdBits, ABits...)
	ABits = append(gasAccountIndexBits, ABits...)
	ABits = append(gasFeeAssetIdBits, ABits...)
	ABits = append(gasFeeAssetAmountBits, ABits...)
	var paddingSize [136]Variable
	for i := 0; i < 136; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	for i := 1; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromMintNft(api API, txInfo MintNftTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeMintNft, TxTypeBitsSize)
	fromAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
	toAccountIndexBits := api.ToBinary(txInfo.ToAccountIndex, AccountIndexBitsSize)
	nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
	gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
	creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize)
	ABits := append(fromAccountIndexBits, txTypeBits...)
	ABits = append(toAccountIndexBits, ABits...)
	ABits = append(nftIndexBits, ABits...)
	ABits = append(gasAccountIndexBits, ABits...)
	ABits = append(gasFeeAssetIdBits, ABits...)
	ABits = append(gasFeeAssetAmountBits, ABits...)
	ABits = append(creatorTreasuryRateBits, ABits...)
	ABits = append(collectionIdBits, ABits...)
	var paddingSize [48]Variable
	for i := 0; i < 48; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = txInfo.NftContentHash
	for i := 2; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromTransferNft(api API, txInfo TransferNftTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeTransferNft, TxTypeBitsSize)
	fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
	toAccountIndexBits := api.ToBinary(txInfo.ToAccountIndex, AccountIndexBitsSize)
	nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
	gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	ABits := append(fromAccountIndexBits, txTypeBits...)
	ABits = append(toAccountIndexBits, ABits...)
	ABits = append(nftIndexBits, ABits...)
	ABits = append(gasAccountIndexBits, ABits...)
	ABits = append(gasFeeAssetIdBits, ABits...)
	ABits = append(gasFeeAssetAmountBits, ABits...)
	var paddingSize [80]Variable
	for i := 0; i < 80; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = txInfo.CallDataHash
	for i := 2; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromAtomicMatch(api API, txInfo AtomicMatchTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeAtomicMatch, TxTypeBitsSize)
	nftIndexBits := api.ToBinary(txInfo.Offer.NftIndex, NftIndexBitsSize)
	submitterAccountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	buyerAccountIndexBits := api.ToBinary(txInfo.Offer.AccountIndex, AccountIndexBitsSize)
	buyerOfferIdBits := api.ToBinary(txInfo.Offer.OfferId, OfferIdBitsSize)
	sellerAccountIndexBits := api.ToBinary(txInfo.Offer.AccountIndex, AccountIndexBitsSize)
	sellerOfferIdBits := api.ToBinary(txInfo.Offer.OfferId, OfferIdBitsSize)
	assetIdBits := api.ToBinary(txInfo.Offer.AssetId, AssetIdBitsSize)
	assetAmountBits := api.ToBinary(txInfo.Offer.AssetAmount, PackedAmountBitsSize)
	creatorAmountBits := api.ToBinary(txInfo.CreatorAmount, PackedAmountBitsSize)
	treasuryAmountBits := api.ToBinary(txInfo.TreasuryAmount, PackedAmountBitsSize)
	gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	ABits := append(submitterAccountIndexBits, txTypeBits...)
	ABits = append(buyerAccountIndexBits, ABits...)
	ABits = append(buyerOfferIdBits, ABits...)
	ABits = append(sellerAccountIndexBits, ABits...)
	ABits = append(sellerOfferIdBits, ABits...)
	ABits = append(nftIndexBits, ABits...)
	ABits = append(assetIdBits, ABits...)
	var paddingSize [48]Variable
	for i := 0; i < 48; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	BBits := append(creatorAmountBits, assetAmountBits...)
	BBits = append(treasuryAmountBits, BBits...)
	BBits = append(gasAccountIndexBits, BBits...)
	BBits = append(gasFeeAssetIdBits, BBits...)
	BBits = append(gasFeeAssetAmountBits, BBits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = api.FromBinary(BBits...)
	for i := 2; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromCancelOffer(api API, txInfo CancelOfferTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeCancelOffer, TxTypeBitsSize)
	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	offerIdBits := api.ToBinary(txInfo.OfferId, OfferIdBitsSize)
	gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	ABits := append(accountIndexBits, txTypeBits...)
	ABits = append(offerIdBits, ABits...)
	ABits = append(gasAccountIndexBits, ABits...)
	ABits = append(gasFeeAssetIdBits, ABits...)
	ABits = append(gasFeeAssetAmountBits, ABits...)
	var paddingSize [128]Variable
	for i := 0; i < 128; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	for i := 1; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromWithdrawNft(api API, txInfo WithdrawNftTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeWithdrawNft, TxTypeBitsSize)
	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	creatorAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
	creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, FeeRateBitsSize)
	nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
	collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
	toAddressBits := api.ToBinary(txInfo.ToAddress, AddressBitsSize)
	gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	ABits := append(accountIndexBits, txTypeBits...)
	ABits = append(creatorAccountIndexBits, ABits...)
	ABits = append(creatorTreasuryRateBits, ABits...)
	ABits = append(nftIndexBits, ABits...)
	ABits = append(collectionIdBits, ABits...)
	var paddingSize [112]Variable
	for i := 0; i < 112; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = txInfo.NftL1Address
	CBits := append(gasAccountIndexBits, toAddressBits...)
	CBits = append(gasFeeAssetIdBits, CBits...)
	CBits = append(gasFeeAssetAmountBits, CBits...)
	pubData[2] = api.FromBinary(CBits...)
	pubData[3] = txInfo.NftContentHash
	pubData[4] = txInfo.NftL1TokenId
	pubData[5] = txInfo.CreatorAccountNameHash
	return pubData
}

func CollectPubDataFromFullExit(api API, txInfo FullExitTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeFullExit, TxTypeBitsSize)
	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
	assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
	ABits := append(accountIndexBits, txTypeBits...)
	ABits = append(assetIdBits, ABits...)
	ABits = append(assetAmountBits, ABits...)
	var paddingSize [72]Variable
	for i := 0; i < 72; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = txInfo.AccountNameHash
	for i := 2; i < PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromFullExitNft(api API, txInfo FullExitNftTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	txTypeBits := api.ToBinary(TxTypeFullExitNft, TxTypeBitsSize)
	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	creatorAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
	creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, FeeRateBitsSize)
	nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
	collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
	ABits := append(accountIndexBits, txTypeBits...)
	ABits = append(creatorAccountIndexBits, ABits...)
	ABits = append(creatorTreasuryRateBits, ABits...)
	ABits = append(nftIndexBits, ABits...)
	ABits = append(collectionIdBits, ABits...)
	var paddingSize [112]Variable
	for i := 0; i < 112; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = txInfo.NftL1Address
	pubData[2] = txInfo.AccountNameHash
	pubData[3] = txInfo.CreatorAccountNameHash
	pubData[4] = txInfo.NftContentHash
	pubData[5] = txInfo.NftL1TokenId
	return pubData
}
