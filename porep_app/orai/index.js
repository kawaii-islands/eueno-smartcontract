const {SigningCosmWasmClient, DirectSecp256k1HdWallet, makeCosmoshubPath} = require("cosmwasm");
const {GasPrice} = require("@cosmjs/stargate");
const {Decimal} = require("@cosmjs/math");

const hdPath = makeCosmoshubPath(0);

const config = {
    topic: "uZXVlbm8tbWFzdGVyLW5vZGU",
    pkKeyVerifyMasterNode: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApdM94qpyHM/F+flQuTGb\nXE2LZfWL+uivn14Goz0L5yL2pNvzBc/yCi7G+0I8+yBLO36SpFG6+TZEOv3Bvnk+\ny0bMqJyEbtFQYahek3UszHonbNprYyvqWUmq1eAFDoggVVIe6QKDaZZshsNxNBYi\n41YZ5Ue7ju6Wkstj9uE8knP+xgz7Uet4j8Nek15gWiia0dPQZ/LLSGPvtP36C89Y\nSfTrepJ4QyrbOA7OAg8fL5afelq3es5zn8jSAZ2U+hbi/zyfI0LRiM5/PsOwBW6R\nQJrFF/fCKs/N1Rbjy441k2XpJJOj1uCXSLtpA+7HlaNl6tJUbjR0ppbxBkD1c5bO\nXQIDAQAB\n-----END PUBLIC KEY-----",
    apiMasterNodeGenesis: "https://master-node.eueno.io/api/v0/pin/ls",
    oraiZkSmartContract: "orai1q3ht02t8ujymqurpqsu7ceaxs6f79q8vxlat3hptrcxef4lwr8tqy2lrtq",
    oraiRpc: "https://testnet-rpc.orai.io",
    oraiLcd: "https://testnet-lcd.orai.io",
    oraiChainId: "Oraichain-testnet",
    oraiPrefix: "orai",
    gasMultiplier: 1.5,
    gasPrice: 0.02,
    sender: "orai1nw5dvqa6j649aaf2hdgqfqa47lpmv77yyu5ulw",
};
const mnemonic = "venture gospel assume erupt trade seed social lake own peasant together that bone kind ability wing sun scrub test coil note pulp train hope";

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

