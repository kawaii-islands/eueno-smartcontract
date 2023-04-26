const crypto = require("crypto");
const {seal, setup} = require("../porep_app");
const {setVerifyParams, submitProof} = require("./orai");

const filePath = `${__dirname}/test.txt`;
console.log(filePath);

const submitProofTest = async () => {

    const porep_id = crypto.randomBytes(32).toString('base64');
    const prover_id = Buffer.from("ab5a507792a559a63a30ff09091c267c454c563c3c6c88dd7c4785f0c63eaadc", "hex").toString("base64");
    const ticket = crypto.randomBytes(32).toString('base64');
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
    const {proof_raw, public_inputs} = seal({
        prover_id,
        porep_id,
        sector_id,
        ticket,
        api_version: setup_params.api_version,
        file_path: filePath,
    });

    console.log("proof_raw", proof_raw);
    let txSetVerify = await setVerifyParams(
        {
            set_verifier_params: {
                params: {setup_params, minimum_challenges: 1, vk: vk_raw},
                sector_size: "sector_size2_kib",
                duration: 1312312,
            },
        });
    console.log("txSetVerify", txSetVerify);

    const submitProofData = {
        submit_proof: {
            api_version: 'V1_0_0',
            porep_id: porep_id,
            prover_id: prover_id,
            proof_raw: proof_raw,
            sector_id: sector_id,
            ticket: ticket,
            public_inputs: public_inputs,
            sector_size: "sector_size2_kib",
        },
    };

    let txSubmitProof = await submitProof(submitProofData);
    console.log("txSubmitProof", txSubmitProof);


};

submitProofTest();
