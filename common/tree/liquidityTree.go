/*
 * Copyright © 2021 Zecrey Protocol
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

package tree

import (
	"github.com/zecrey-labs/zecrey-crypto/accumulators/merkleTree"
	"github.com/zecrey-labs/zecrey-crypto/hash/bn254/zmimc"
	"github.com/zecrey-labs/zecrey-legend/common/model/liquidity"
	"github.com/zeromicro/go-zero/core/logx"
	"log"
)

// TODO replace history as liquidity + liquidityHistory
func InitLiquidityTree(
	liquidityHistoryModel LiquidityHistoryModel,
	blockHeight int64,
) (
	liquidityTree *Tree, err error,
) {
	liquidityAssets, err := liquidityHistoryModel.GetLatestLiquidityByBlockHeight(blockHeight)
	if err != nil {
		if err != liquidity.ErrNotFound {
			logx.Errorf("[InitNftTree] unable to get latest nft assets: %s", err.Error())
			return nil, err
		} else {
			liquidityTree, err = NewEmptyLiquidityTree()
			if err != nil {
				log.Println("[InitNftTree] unable to create empty tree:", err)
				return nil, err
			}
			return liquidityTree, nil
		}
	}
	// empty tree
	if len(liquidityAssets) == 0 {
		liquidityTree, err = NewEmptyLiquidityTree()
		if err != nil {
			log.Println("[InitNftTree] unable to create empty tree:", err)
			return nil, err
		}
		return liquidityTree, nil
	}

	liquidityAssetsMap := make(map[int64]*Node)
	for _, liquidityAsset := range liquidityAssets {
		pairIndex := liquidityAsset.PairIndex
		node, err := LiquidityAssetToNode(
			liquidityAsset.AssetAId, liquidityAsset.AssetA,
			liquidityAsset.AssetBId, liquidityAsset.AssetB,
			liquidityAsset.LpAmount, liquidityAsset.KLast,
			liquidityAsset.FeeRate, liquidityAsset.TreasuryAccountIndex, liquidityAsset.TreasuryRate)
		if err != nil {
			logx.Errorf("[InitNftTree] unable to convert nft asset to node: %s", err.Error())
			return nil, err
		}
		liquidityAssetsMap[pairIndex] = node
	}
	liquidityTree, err = merkleTree.NewTreeByMap(liquidityAssetsMap, LiquidityTreeHeight, NilLiquidityNodeHash, zmimc.Hmimc)
	if err != nil {
		logx.Errorf("[InitNftTree] unable to create new tree by map")
		return nil, err
	}
	return liquidityTree, nil
}
