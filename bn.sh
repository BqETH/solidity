#!/bin/bash
curl localhost:8545 -X POST --header 'Content-type: application/json' --data '{"jsonrpc":"2.0", "method":"eth_blockNumber", "id":1}' 2>/dev/null | sed "s|\$|\n|"
