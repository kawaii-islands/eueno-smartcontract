const {setup, seal} = require('./dist');
const path = require('path');

const start = Date.now();

console.log("start", start);
const porep_id = Buffer.from([55, 32]).toString('base64');
const prover_id = Buffer.from([55, 32]).toString('base64');
const ret = setup({
    porep_id,
    api_version: '1.0.0',
    sector_size: 'sector_size2_kib',
});
console.log("ret", JSON.parse(ret).setup_params);
const {proof_raw, public_inputs} = seal({
    // secret random
    api_version: '1.0.0',
    porep_id,
    prover_id,
    setup_params: JSON.stringify(JSON.parse(ret).setup_params),
    file_path: "/Users/admin/Desktop/This-pc/orai/eueno-proof-of-replication/porep_app/file_2kiB.txt",
});

// //
console.log(proof_raw);
console.log('Took', Date.now() - start, 'ms');

