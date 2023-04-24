const { seal_and_verify } = require("./src/verify");

async function main() {
  let porep_id = "abcd"; // hex string, even length
  let prover_id = "cd3211"; // hex string, even length
  let sector_id = 54; // u64
  let seed = "6785"; // hex string, even length
  let ticket = "849837"; // hex string, even length
  let api_version = "1.1.0";
  let path = "file_2kiB.txt";

  const valid = await seal_and_verify(
    path,
    porep_id,
    api_version,
    prover_id,
    sector_id,
    seed,
    ticket
  );

  console.log(`Validation result: ${valid}`)
}

main().then((err) => console.error(err));
