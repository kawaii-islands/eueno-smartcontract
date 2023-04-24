const { SigningCosmWasmClient } = require("@cosmjs/cosmwasm-stargate");
const { exec } = require("child_process");
const addresses = require("./addresses.json");
const { api_versions } = require("../constants");
const dotenv = require("dotenv");
dotenv.config();

const queryContract = async (address, input) => {
  const client = await SigningCosmWasmClient.connect(
    process.env.RPC_URL || "https://testnet-rpc.orai.io"
  );
  const queryResult = await client.queryContractSmart(address, input);
  return queryResult;
};

const seal_and_verify = async (
  path,
  porep_id,
  api_version = "1.0.0",
  prover_id,
  sector_id,
  seed,
  ticket
) => {
  const address = addresses.verifier;
  exec(
    `./porep_app seal ${path} --api-version ${api_version} --porep-id ${porep_id} ${
      prover_id ? `--prover-id ${prover_id}` : ""
    } ${sector_id ? `--sector-id ${sector_id}` : ""} ${
      seed ? `--seed ${seed}` : ""
    } ${ticket ? `--ticket ${ticket}` : ""}`,
    async (error, stdout, stderr) => {
      if (error) {
        throw error;
      }
      if (stderr) {
        throw stderr;
      }
      const query_data = JSON.parse(stdout);

      const params = {
        porep_id,
        api_version: api_versions[api_version],
        sector_size: query_data.sector_size,
        proof_raw: query_data.proof_le,
        public_inputs: JSON.parse(query_data.public_inputs),
      };
      console.log(params);

      const query_result = await queryContract(address, {
        VerifyProof: params,
      });

      return query_result;
    }
  );
};

module.exports = { seal_and_verify };
