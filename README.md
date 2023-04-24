# Eueno-proof-of-replication

> This library is a folk of [Filecoin Proof of Replication library](https://github.com/filecoin-project/rust-fil-proofs/tree/master/storage-proofs-porep).

An module being responsible for proving and verifying the availability of some pieces of data in certain data nodes of Eueno storage system.

## Use case

The module contains to 2 main actors: Prover - Eueno's node which stores data, Verifier - Cosmwasm Smart Contract.

At a certain point of time, when being asked, the prover must create a Snark proof that convinces the verifier that the node actually holds the required piece of data.

In the following parts, we will cover all detailed steps that need to be done by provers and verifiers to implement the protocol.

# Parameters
There are 3 types of parameters

* Common Parameters: used by both Verifier and Prover in each Porep time. Verifier contract owner use them to precompute verifying keys.
* Proving Parameters: used by Prover to seal files, calculate Groth16 proofs, public inputs and auxiliary information.

## Common Parameters

Verifying parameters include some necessary information that the smart contract need to verify proof of replication pushed on by provers. They should be precomputed off-chain and set by the contract owner.

1. **Porep Id**: arbitrary 32 bytes, passed as hex string(ex: "0x4719723ab"), as its name suggests, **Porep Id** identifies each Proof of replication
2. **Sector Size**: size of proved files, here's the list of supported file sizes (in this protocol, we often refer file as sector):
```js
const sector_sizes = {
  "sector-size2-kib": 1<<11,
  "sector-size4-kib": 1<<12,
  "sector-size16-kib": 1<<14,
  "sector-size32-kib": 1<<15,
  "sector-size8-mib": 1<<23,
  "sector-size16-mib": 1<<24,
  "sector-size512-mib": 1<<29,
  "sector-size1-gib": 1<<30,
  "sector-size32-gib": 1<<35,
  "sector-size64-gib": 1<<36,
};
```
3. **API Version**: Currently, we implement Porep Argorithm in 2 ways, corresponding with 2 API Versions
```js
const api_versions = {
  "1.0.0": "V1_0_0",
  "1.1.0": "V1_1_0",
};
```


## Proving Parameters

Apart from passing common parameters, prover should add some additional information to specify the proved file, prover id, sector id, ticket, seed

1. **Prover Id, Ticket, Seed**: arbitrary 32 bytes, passed as hex string(ex: "0x4719723ab")

2. **Sector Id**: u64 number (ex: 31774937)

# Deployment and Examples

## Deploy Porep Application with Docker

1. Feature opencl
```bash
docker build -t porep_app -f dockerfiles/opencl/Dockerfile .
```

2. Feature cuda
```bash
docker build -t porep_app -f dockerfiles/cuda/Dockerfile .
```
## Example for Contract Admin
```
cd admin-node
npm i
cp .env.sample .env
// specify your mnemonic in .env file
node example.js
```

## Example for Prover
```
cd prover-node
npm i
cp .env.sample .env
node example.js
```