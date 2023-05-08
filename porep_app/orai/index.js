require('dotenv').config();
const {SigningCosmWasmClient, DirectSecp256k1HdWallet, makeCosmoshubPath} = require("cosmwasm");
const {GasPrice} = require("@cosmjs/stargate");
const {Decimal} = require("@cosmjs/math");

const hdPath = makeCosmoshubPath(0);

const config = {
    oraiZkSmartContract: process.env.ORAI_ZK_CONTRACT,
    oraiRpc: "https://testnet-rpc.orai.io",
    oraiLcd: "https://testnet-lcd.orai.io",
    oraiChainId: "Oraichain-testnet",
    oraiPrefix: "orai",
    gasMultiplier: 1.5,
    gasPrice: 0.02,
    sender: "orai1nw5dvqa6j649aaf2hdgqfqa47lpmv77yyu5ulw",
};
const mnemonic = process.env.MNEMONIC;

module.exports = {
    setVerifyParams: async (params) => {
        try {
            const offlineSigner = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
                prefix: config.oraiPrefix,
                hdPaths: [hdPath],
            });

            const client = await SigningCosmWasmClient.connectWithSigner(
                config.oraiRpc,
                offlineSigner,
                {
                    prefix: config.oraiPrefix,
                    gasPrice: new GasPrice(Decimal.fromUserInput('0.01', 6), "orai"),
                },
            );

            const res = await client.execute(
                config.sender,
                config.oraiZkSmartContract,
                params,
                'auto',
                "",
                [],
            );
            return {
                status: 200,
                transactionHash: res.transactionHash,
            };
        } catch (e) {
            console.log(e);
            return `error query current round ${e}`;
        }
    },
    verify: async (params) => {
        try {
            const offlineSigner = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
                prefix: config.oraiPrefix,
                hdPaths: [hdPath],
            });

            const client = await SigningCosmWasmClient.connectWithSigner(
                config.oraiRpc,
                offlineSigner,
                {
                    prefix: config.oraiPrefix,
                    gasPrice: new GasPrice(Decimal.fromUserInput('0.01', 6), "orai"),
                },
            );

            const result = await client.queryContractSmart(config.oraiZkSmartContract, params);
            return result;
        } catch (e) {
            console.log(`error verify ${e}`);
        }
    },
    query: async (params) => {
        try {
            const offlineSigner = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
                prefix: config.oraiPrefix,
                hdPaths: [hdPath],
            });

            const client = await SigningCosmWasmClient.connectWithSigner(
                config.oraiRpc,
                offlineSigner,
                {
                    prefix: config.oraiPrefix,
                    gasPrice: new GasPrice(Decimal.fromUserInput('0.01', 6), "orai"),
                },
            );

            const result = await client.queryContractSmart(config.oraiZkSmartContract, params);
            return result;
        } catch (e) {
            console.log(`error verify ${e}`);
        }
    },
    submitProof: async (params) => {
        try {
            const offlineSigner = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
                prefix: config.oraiPrefix,
                hdPaths: [hdPath],
            });

            const client = await SigningCosmWasmClient.connectWithSigner(
                config.oraiRpc,
                offlineSigner,
                {
                    prefix: config.oraiPrefix,
                    gasPrice: new GasPrice(Decimal.fromUserInput('0.01', 6), "orai"),
                },
            );

            const res = await client.execute(
                config.sender,
                config.oraiZkSmartContract,
                params,
                'auto',
                "",
                [],
            );
            return {
                status: 200,
                transactionHash: res.transactionHash,
            };
        } catch (e) {
            return `error submit round ${e}`;
        }
    },
};

