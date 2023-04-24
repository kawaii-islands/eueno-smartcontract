const { DirectSecp256k1HdWallet } = require("@cosmjs/proto-signing");
const { stringToPath } = require("@cosmjs/crypto");
const cosmwasm = require("@cosmjs/cosmwasm-stargate");
const { GasPrice } = require("@cosmjs/stargate");
const { exec } = require("child_process");
const addresses = require("./addresses.json");
const config = require("../config.json");
const dotenv = require("dotenv");
const { sector_sizes, api_versions } = require("../constants");
dotenv.config();

const collectWallet = async (mnemonic) => {
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
    hdPaths: [stringToPath("m/44'/118'/0'/0/0")],
    prefix: config.network.prefix,
  });
  return wallet;
};

const execute = async (mnemonic, address, handleMsg, memo, amount, gasData) => {
  try {
    const wallet = await collectWallet(mnemonic);
    const [firstAccount] = await wallet.getAccounts();
    const client = await cosmwasm.SigningCosmWasmClient.connectWithSigner(
      config.network.rpc,
      wallet,
      {
        gasPrice: gasData
          ? GasPrice.fromString(`${gasData.gasAmount}${gasData.denom}`)
          : GasPrice.fromString(`0.25${config.network.prefix}`),
        prefix: config.network.prefix,
        gasLimits: { exec: 20000000 },
      }
    );
    const result = await client.execute(
      firstAccount.address,
      address,
      handleMsg,
      "auto",
      memo,
      amount
    );
    return result.transactionHash;
  } catch (error) {
    console.log("error in executing contract: ", error);
    throw error;
  }
};

async function set_verifier_params(
  porep_id,
  sector_size = "sector-size2-kib",
  api_version = "1.0.0"
) {
  const mnemonic = process.env.MNEMONIC;

  let address = addresses.verifier;

  exec(
    `./porep_app setup --porep-id ${porep_id} ${
      api_version ? `--api-version ${api_version}` : ""
    } --sector-size ${sector_size}`,
    async (error, stdout, stderr) => {
      if (error) {
        throw error;
      }
      if (stderr) {
        throw stderr;
      }
      const exec_data = JSON.parse(stdout);

      let verifier_params = {
        setup_params: exec_data.setup_params,
        minimum_challenges: exec_data.minimum_challenges,
        vk: exec_data.vk_le,
      };

      let params = {
        porep_id,
        sector_size: sector_sizes[sector_size],
        api_version: api_versions[api_version],
        params: verifier_params,
      };

      console.log(params);
      const txs = await execute(mnemonic, address, {
        SetVerifierParams: params,
      });
      console.log(`Setup parameter successfully, txs: ${txs}`);
    }
  );
}

module.exports = { set_verifier_params };
