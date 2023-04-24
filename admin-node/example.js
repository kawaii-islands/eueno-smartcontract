const { set_verifier_params } = require("./src/set_verifier_params");
const { seal_and_verify } = require("./src/verify");

async function main() {
  let porep_id = "abcd"; // hex string, even length
  let prover_id = "cd3211"; // hex string, even length
  let sector_id = 54; // u64
  let seed = "6785"; // hex string, even length
  let ticket = "849837"; // hex string, even length
  let sector_size = "sector-size2-kib";
  let api_version = "1.1.0";
  let path = "file_2kiB.txt";

  await set_verifier_params(porep_id, sector_size, api_version);
}

main().then((err) => console.error(err));
