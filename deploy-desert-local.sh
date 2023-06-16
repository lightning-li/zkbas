#!/bin/bash

# Preparation: Install following tools when you first run this script!!!
# GOBIN=/usr/local/bin/ go install  github.com/zeromicro/go-zero/tools/goctl@1.5.1
# yum install jq -y
# npm install pm2 -g
# You should install nodejs above v14
# sh deploy-local.sh new  // append the new parameter to generate pk and vk data when you first run this script.
##
# Attention: Set the following variables to the right one before running!!!
ZkBNB_REPO_PATH=$(cd `dirname $0`; pwd)

export PATH=$PATH:/usr/local/go/bin:/usr/local/go/bin:/root/go/bin
echo 'start install'
ZKBNB_CONTAINERS=$(docker ps -a |grep zkbnb-desert|awk '{print $1}')
[[ -z "${ZKBNB_CONTAINERS}" ]] || docker rm -f ${ZKBNB_CONTAINERS}
docker run -d --name zkbnb-desert-kvrocks -p 6666:6666 apache/kvrocks
docker run -d --name zkbnb-desert-postgres -p 5434:5432 \
  -e PGDATA=/var/lib/postgresql/pgdata  \
  -e POSTGRES_PASSWORD=ZkBNB@123 \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_DB=zkbnb_desert postgres

export PATH=$PATH:/usr/local/go/bin/


echo 'install dependency'

make api-server
cd ${ZkBNB_REPO_PATH} && go mod tidy

sleep 10s


echo "
Name: desertexit

Postgres:
  MasterDataSource: host=127.0.0.1 user=postgres password=ZkBNB@123 dbname=zkbnb_desert port=5434 sslmode=disable
  LogLevel: 4

ChainConfig:
  ConfirmBlocksCount: 0
  MaxWaitingTime: 120
  MaxHandledBlocksCount: 5000
  MaxCancelOutstandingDepositCount: 100
  KeptHistoryBlocksCount: 100000
  GasLimit: 5000000

  StartL1BlockHeight: 1
  BscTestNetRpc: http://127.0.0.1:8545
  ZkBnbContractAddress: 0xA22aF4928B6eFfD757C0caf2109f6bFD1bF36109
  GovernanceContractAddress: 0xbFC91670c863393601Abf76C9cafdf5278bBAccA

TreeDB:
  Driver: redis
  RedisDBOption:
    Addr: localhost:6666
    DialTimeout: 10s
    ReadTimeout: 10s
    WriteTimeout: 10s
    PoolTimeout: 15s
    IdleTimeout: 5m
    PoolSize: 500
    MaxRetries: 3
    MinRetryBackoff: 8ms
    MaxRetryBackoff: 512ms
  AssetTreeCacheSize: 10000000
CacheConfig:
  AccountCacheSize: 10000000
  NftCacheSize: 10000000
  MemCacheSize: 1000000

KeyPath: /Users/likang/.zkbnb/zkbnb.desert1

  " > ${ZkBNB_REPO_PATH}/tools/desertexit/etc/config.yaml

echo 'end install'
