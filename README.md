# _Proof of Work_

## How to run (2 options)
1. modify execution configuration and enter PID ``0 | 1 | 2`` as CLI argument and run Blockchain.main()
   1. **[OPTIONAL]** Give respective execution configuration a name/id for clarity `Blockchain 0 | Blockchain 1 | Blockchain 2`
   2. run each config file starting from 0
   
2. In root directory, run `docker-compose up -d` from command line

## verifying with JQ
- ```cat BlockChainLedger.json | jq '. | length'``` : should always be 13 blocks
  - 1 dodgy block record
  - 4 legit block record for each process (4*3=12)
- ```cat BlockChainLedger.json | jq ``` :  to view ledger in pretty print json
  - ensure block id is incremental
  - ensure verified blocks are not duplicated and only appear once
  - ensure winning hash continues to be used to build next block
  - ensure all processes are participating in the blockchain protocol

    