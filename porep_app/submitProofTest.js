const crypto = require("crypto");
const {seal, setup} = require("../porep_app");
const {setVerifyParams, submitProof} = require("./orai");

const filePath = `${__dirname}/test.txt`;
console.log(filePath);

const submitProofTest = async () => {

    const porep_id = "CCfpg6EwKekgRlZp6nOD5Ua6h/dnX8CrsYqtssj02hQ=";
    const prover_id = Buffer.from("ab5a507792a559a63a30ff09091c267c454c563c3c6c88dd7c4785f0c63eaadc", "hex").toString("base64");
    const ticket = "A/Zs66rqKf/eItl8zetZ1ct3GSqeEG4CH0K4Zlknqh0=";
    const sector_id = 1;

    console.log("==================>");
    console.log(`${new Date(Date.now())} == ${Date.now()} ==== start round new ====>`);
    console.log("porep_id", porep_id);
    console.log("prover_id", prover_id);
    console.log("ticket", ticket);
    console.log("sector_id", sector_id);

    const start = Date.now();
    console.log("start", start);

    const {setup_params, vk_raw} = setup({
        porep_id,
        api_version: 'V1_0_0',
        sector_size: 'sector_size2_kib',
    });
    console.log("setup_params", JSON.stringify(setup_params));
    console.log("vk_raw", JSON.stringify(vk_raw));

    console.log("data seal =>>>>>>", JSON.stringify({
        prover_id,
        porep_id,
        sector_id,
        ticket,
        api_version: setup_params.api_version,
        file_path: filePath,
    }));
    const {proof_raw, public_inputs} = seal({
        prover_id,
        porep_id,
        sector_id,
        ticket,
        api_version: setup_params.api_version,
        file_path: filePath,
    });

    console.log("proof_raw", JSON.stringify(proof_raw));
    console.log("public_inputs", JSON.stringify(public_inputs));
    // let txSetVerify = await setVerifyParams(
    //     {
    //         set_verifier_params: {
    //             params: {setup_params, minimum_challenges: 1, vk: vk_raw},
    //             sector_size: "sector_size2_kib",
    //             duration: 1312312,
    //         },
    //     });
    // console.log("txSetVerify", txSetVerify);

    // const submitProofData = {
    //     submit_proof: {
    //         api_version: 'V1_0_0',
    //         porep_id: porep_id,
    //         prover_id: prover_id,
    //         proof_raw: proof_raw,
    //         sector_id: sector_id,
    //         ticket: ticket,
    //         public_inputs: public_inputs,
    //         sector_size: "sector_size2_kib",
    //     },
    // };
    //
    // let txSubmitProof = await submitProof(submitProofData);
    // console.log("txSubmitProof", txSubmitProof);


};

submitProofTest();
