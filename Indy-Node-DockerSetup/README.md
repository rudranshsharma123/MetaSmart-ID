# Modified Indy network docker image for Indy Node, Plenum and Pools

This folder contains configurations for setting up a reference Pool implementation based on a modified version of [`indy-plenum`](https://github.com/hyperledger/indy-plenum).



## Requirements

Docker-Compose: Version 1.29.2 or above

**Not compatible with docker version >= 2** 


## Starting a network

The `docker` folder contains the test IIN docker image, along with scripts to start a test IIN network. 

```
cd docker
```


Build IIN docker image:
```
make image
```

Run sample IIN docker container running 4 Indy nodes:
```
make start
```

## Stopping a Test IIN network
```
make stop
```

Clean ledger data and generated artifacts.

```
make clean
```

## Configuring the network

The Indy network is a public permissioned network where nodes having roles 'stewards' or 'trustees' can only perform transactions. The ledger can however be queried by any non-participating entity also.

You can configure how many nodes (stewards) run the Test IIN network through environment variables.

For running the Test IIN with 10 nodes and 10 clients:
```
INDYNODES=10 INDYCLIENTS=10 make start
```

Here, the first node uses the ports 9701 and 9702. The second node uses 9703 and 9704. And so on.

## Connecting to the network

Use the genesis block `indy_sandbox/pool_transactions_genesis` to connect to the network using `indy-sdk`.
It needs the indy-sdk to be built

