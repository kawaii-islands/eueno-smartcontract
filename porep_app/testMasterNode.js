const crypto = require("crypto");
const {seal, setup} = require("../porep_app");
const {setVerifyParams, verify} = require("./orai");

const filePath = `${__dirname}/test.txt`;
console.log(filePath);

const testMasterNode = async () => {

    const porep_id = "6aB+mljoMLXqSAywTc3yyoTolJGCgY2YZNBLtvu0kYU=";
    const prover_id = Buffer.from("5b94c91ea7b5e358da43ffbb07e6ec3a0f9c81fc5b5d30b5feb58aa0a52bcf61", "hex").toString("base64");
    const ticket = crypto.randomBytes(32).toString('base64');
    const sector_id = 1;
    const api_version = "V1_0_0";
    const sector_size = "sector_size2_kib";

    const start = Date.now();
    console.log("start", start);
    const {setup_params, vk_raw} = setup({
        porep_id,
        api_version,
        sector_size,
    });

    let txSetVerify = await setVerifyParams(
        {
            set_verifier_params: {
                params: {setup_params, minimum_challenges: 1, vk: vk_raw},
                sector_size: "sector_size2_kib",
                duration: 100000,
            },
        });
    console.log("txSetVerify", txSetVerify);


    // const {proof_raw, public_inputs} = seal({
    //     prover_id,
    //     porep_id,
    //     sector_id,
    //     ticket,
    //     api_version,
    //     file_path: filePath,
    // });
    //
    // console.log("proof_raw", JSON.stringify(proof_raw));
    // console.log("public_inputs", JSON.stringify(public_inputs));

    // console.log([...Buffer.from(porep_id, 'base64')]);
    // const submitProofData = {
    //     verify_proof: {
    //         api_version: 'V1_0_0',
    //         porep_id: [...Buffer.from(porep_id, 'base64')],
    //         prover_id: prover_id,
    //         proof_raw: proof_raw,
    //         sector_id: sector_id,
    //         ticket: ticket,
    //         public_inputs: public_inputs,
    //         sector_size: "sector_size2_kib",
    //     },
    // };
    //
    // let resultVerify = await verify(submitProofData);
    // console.log("resultVerify", resultVerify);


};

testMasterNode();
