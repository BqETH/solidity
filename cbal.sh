#!/bin/bash 

KHADAS="http://192.168.0.140:8545"
#KHADAS="http://71.218.165.179:8545"

json=`curl -i -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x5fbdb2315678afecb367f032d93f642f64180aa3","latest"],"id":1}' "$KHADAS" 2>/dev/null `
hexNum=`echo $json | sed  "s|.*result\":\"\(.*\)\".*|\1|"` 
decNum=`printf "%d\n" $hexNum`
echo "scale=4; $decNum/1000000000000000000" | bc
#hexNum=`echo $hexNum | sed "s|0x||" | sed 's/[a-z]/\U&/g' `
#echo "ibase=16; obase=10; $hexNum/DE0B6B3A7640000" | bc
