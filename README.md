# _Proof of Work_

## How to run
- Navigate (cd) to root directory
- compile with GSON jar : ```javac -cp ".:gson-2.8.2.jar" Blockchain.java```
- create a iTerm2 profile that would automatically navigate to root directory on startup
- run the start script (MAC) : ```osascript startup.scpt```


## verifying with JQ
- ```cat BlockChainLedger.json | jq '. | length'``` : should always be 13 blocks
  - 1 dodgy block record
  - 4 legit block record for each process (4*3=12)
- ```cat BlockChainLedger.json | jq ``` :  to view ledger in pretty print json
  - ensure block id is incremental
  - ensure verified blocks are not duplicated and only appear once
  - ensure winning hash continues to be used to build next block
  - ensure all processes are participating in the blockchain protocol


