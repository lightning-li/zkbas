/*
 * Copyright © 2021 ZkBNB Protocol
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
	"bytes"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"

	bsmt "github.com/bnb-chain/zkbnb-smt"
	common2 "github.com/bnb-chain/zkbnb/common"
)

func EmptyAccountNodeHash() []byte {
	/*
		AccountNameHash
		PubKey
		Nonce
		CollectionNonce
		AssetRoot
	*/
	zero := fr.Zero()
	NilAccountAssetRootElement := fr.FromBigInt(new(big.Int).SetBytes(NilAccountAssetRoot))
	hash := poseidon.Poseidon(zero, zero, zero, zero, zero, NilAccountAssetRootElement).Bytes()
	return hash[:]
}

func EmptyAccountAssetNodeHash() []byte {
	/*
		balance
		offerCanceledOrFinalized
	*/
	zero := fr.Zero()
	hash := poseidon.Poseidon(zero, zero).Bytes()
	return hash[:]
}

func EmptyNftNodeHash() []byte {
	/*
		creatorAccountIndex
		ownerAccountIndex
		nftContentHash
		creatorTreasuryRate
		collectionId
	*/
	zero := fr.Zero()
	hash := poseidon.Poseidon(zero, zero, zero, zero, zero, zero, zero).Bytes()
	return hash[:]
}

func CommitTrees(
	pool *ants.Pool,
	version uint64,
	accountTree bsmt.SparseMerkleTree,
	assetTrees *AssetTreeCache,
	nftTree bsmt.SparseMerkleTree) error {

	assetTreeChanges := assetTrees.GetChanges()
	defer assetTrees.CleanChanges()
	totalTask := len(assetTreeChanges) + 2

	errChan := make(chan error, totalTask)
	defer close(errChan)

	err := pool.Submit(func() {
		accPrunedVersion := bsmt.Version(version)
		if accountTree.LatestVersion() < accPrunedVersion {
			accPrunedVersion = accountTree.LatestVersion()
		}
		ver, err := accountTree.Commit(&accPrunedVersion)
		if err != nil {
			errChan <- errors.Wrapf(err, "unable to commit account tree, tree ver: %d, prune ver: %d", ver, accPrunedVersion)
			return
		}
		errChan <- nil
	})
	if err != nil {
		return err
	}

	for _, idx := range assetTreeChanges {
		err := func(i int64) error {
			return pool.Submit(func() {
				asset := assetTrees.Get(i)
				version := asset.LatestVersion()
				ver, err := asset.Commit(&version)
				if err != nil {
					errChan <- errors.Wrapf(err, "unable to commit asset tree [%d], tree ver: %d, prune ver: %d", i, ver, version)
					return
				}
				errChan <- nil
			})
		}(idx)
		if err != nil {
			return err
		}
	}

	err = pool.Submit(func() {
		nftPrunedVersion := bsmt.Version(version)
		if nftTree.LatestVersion() < nftPrunedVersion {
			nftPrunedVersion = nftTree.LatestVersion()
		}
		ver, err := nftTree.Commit(&nftPrunedVersion)
		if err != nil {
			errChan <- errors.Wrapf(err, "unable to commit nft tree, tree ver: %d, prune ver: %d", ver, nftPrunedVersion)
			return
		}
		errChan <- nil
	})
	if err != nil {
		return err
	}

	for i := 0; i < totalTask; i++ {
		err := <-errChan
		if err != nil {
			return err
		}
	}

	return nil
}

func RollBackTrees(
	pool *ants.Pool,
	version uint64,
	accountTree bsmt.SparseMerkleTree,
	assetTrees *AssetTreeCache,
	nftTree bsmt.SparseMerkleTree) error {

	assetTreeChanges := assetTrees.GetChanges()
	defer assetTrees.CleanChanges()
	totalTask := len(assetTreeChanges) + 3
	errChan := make(chan error, totalTask)
	defer close(errChan)

	ver := bsmt.Version(version)
	err := pool.Submit(func() {
		if accountTree.LatestVersion() > ver && !accountTree.IsEmpty() {
			err := accountTree.Rollback(ver)
			if err != nil {
				errChan <- errors.Wrapf(err, "unable to rollback account tree, ver: %d", ver)
				return
			}
		}
		errChan <- nil
	})
	if err != nil {
		return err
	}

	for _, idx := range assetTreeChanges {
		err := func(i int64) error {
			return pool.Submit(func() {
				asset := assetTrees.Get(i)
				version := asset.RecentVersion()
				err := asset.Rollback(version)
				if err != nil {
					errChan <- errors.Wrapf(err, "unable to rollback asset tree [%d], ver: %d", i, version)
					return
				}
				errChan <- nil
			})
		}(idx)
		if err != nil {
			return err
		}
	}

	err = pool.Submit(func() {
		if nftTree.LatestVersion() > ver && !nftTree.IsEmpty() {
			err := nftTree.Rollback(ver)
			if err != nil {
				errChan <- errors.Wrapf(err, "unable to rollback nft tree, tree ver: %d", ver)
				return
			}
		}
		errChan <- nil
	})
	if err != nil {
		return err
	}

	for i := 0; i < totalTask; i++ {
		err := <-errChan
		if err != nil {
			return err
		}
	}

	return nil
}

func ComputeAccountLeafHash(
	accountNameHash string,
	pk string,
	nonce int64,
	collectionNonce int64,
	assetRoot []byte,
) (hashVal []byte, err error) {
	e0 := fr.FromHex(accountNameHash)
	pubKey, err := common2.ParsePubKey(pk)
	if err != nil {
		return nil, err
	}
	e1 := &pubKey.A.X
	e2 := &pubKey.A.Y
	e3 := fr.FromBigInt(new(big.Int).SetInt64(nonce))
	e4 := fr.FromBigInt(new(big.Int).SetInt64(collectionNonce))
	e5 := fr.FromBigInt(new(big.Int).SetBytes(assetRoot))
	hash := poseidon.Poseidon(e0, e1, e2, e3, e4, e5).Bytes()
	return hash[:], nil
}

func ComputeAccountAssetLeafHash(
	balance string,
	offerCanceledOrFinalized string,
) (hashVal []byte, err error) {
	balanceBigInt, isValid := new(big.Int).SetString(balance, 10)
	if !isValid {
		return nil, errors.New("invalid balance string")
	}
	e0 := fr.FromBigInt(balanceBigInt)

	offerCanceledOrFinalizedBigInt, isValid := new(big.Int).SetString(offerCanceledOrFinalized, 10)
	if !isValid {
		return nil, errors.New("invalid balance string")
	}
	e1 := fr.FromBigInt(offerCanceledOrFinalizedBigInt)
	hash := poseidon.Poseidon(e0, e1).Bytes()
	return hash[:], nil
}

func ComputeNftAssetLeafHash(
	creatorAccountIndex int64,
	ownerAccountIndex int64,
	nftContentHash string,
	nftL1Address string,
	nftL1TokenId string,
	creatorTreasuryRate int64,
	collectionId int64,
) (hashVal []byte, err error) {
	e0 := fr.FromBigInt(new(big.Int).SetInt64(creatorAccountIndex))
	e1 := fr.FromBigInt(new(big.Int).SetInt64(ownerAccountIndex))
	e2 := fr.FromHex(nftContentHash)
	var buf bytes.Buffer
	err = common2.PaddingAddressIntoBuf(&buf, nftL1Address)
	if err != nil {
		return nil, err
	}
	e5 := fr.FromBigInt(new(big.Int).SetBytes(buf.Bytes()))
	nftL1TokenIdBigInt, isValid := new(big.Int).SetString(nftL1TokenId, 10)
	if !isValid {
		return nil, errors.New("invalid balance string")
	}
	e6 := fr.FromBigInt(nftL1TokenIdBigInt)
	e3 := fr.FromBigInt(new(big.Int).SetInt64(creatorTreasuryRate))
	e4 := fr.FromBigInt(new(big.Int).SetInt64(collectionId))
	hash := poseidon.Poseidon(e0, e1, e2, e5, e6, e3, e4).Bytes()
	return hash[:], nil
}

func ComputeStateRootHash(
	accountRoot []byte,
	nftRoot []byte,
) []byte {
	e0 := fr.FromBigInt(new(big.Int).SetBytes(accountRoot))
	e1 := fr.FromBigInt(new(big.Int).SetBytes(nftRoot))
	hash := poseidon.Poseidon(e0, e1).Bytes()
	return hash[:]
}
