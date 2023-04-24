import {config as cosmosConfig} from '../cosmjs.config'
import {calculateFee, GasPrice} from '@cosmjs/stargate'
import {InstantiateMsg} from '../build/Contract.types'
import {ContractClient} from '../build/Contract.client'
import * as fs from 'fs'
import * as path from 'path'
import {setUp} from './setUp'
import config from '../config'
// @ts-ignore
import crypto from "crypto";
// @ts-ignore
import {seal, setup} from "../../admin-node/porep_app";

const orainTestnet = cosmosConfig.networks.oraichain_testnet

const filePath = path.resolve(__dirname, "test.txt");

console.log("filePath", filePath)

async function main() {
    // create wallet
    const {cc: client, wallet} = await setUp()
    const accounts = await wallet.getAccounts()
    const owner = accounts[0].address

    const initMsg: InstantiateMsg = {}

    const wasmPath = path.resolve(
        __dirname,
        '../artifacts/contract.wasm'
    )
    console.log("wasmPath", wasmPath)
    const wasm = fs.readFileSync(wasmPath)
    // upload calculate Fee
    const uploadFee = calculateFee(0, GasPrice.fromString(orainTestnet.gasPrice))
    console.log('=>uploadFee', uploadFee)
    const uploadResult = await client.upload(owner, wasm, 'auto')
    console.log('==>Codeid', uploadResult.codeId)

    const contract = await client.instantiate(
        owner,
        uploadResult.codeId,
        // @ts-ignore
        initMsg,
        'MEME',
        'auto'
    )
    console.log('contract address: ', contract.contractAddress)

    const porep_id = "66z5mSlp7IIEcrHMxnzkG7TBHZRphpbw6m1Y/x63xm4="
    const prover_id = Buffer.from("ab5a507792a559a63a30ff09091c267c454c563c3c6c88dd7c4785f0c63eaadc", "hex").toString("base64")
    const sector_id = 1
    const ticket = "5JPQJmEEv48MrF0uMLd4YZMc7FJklqOBLGsAs/+qGZA="

    console.log("==================>")
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
        sector_size: 'sector_size2_kib'
    });
    console.log("setup_params", setup_params)

    const zkClient = new ContractClient(
        client,
        owner,
        contract.contractAddress
    )
    let res = await zkClient.setVerifierParams({
        params: {setup_params, minimum_challenges: 1, vk: vk_raw},
        sectorSize: 'sector_size2_kib',
        duration: 12312
    })

    console.log("setVerifierParams", res)
    const {proof_raw, public_inputs} = seal({
        prover_id,
        porep_id,
        sector_id,
        ticket,
        api_version: setup_params.api_version,
        file_path: filePath
    });
    console.log("public_inputs", public_inputs)
    console.log("proof_raw", proof_raw)

    let submitVerify = await zkClient.submitProof({
        apiVersion: 'V1_0_0',
        porepId: porep_id,
        proverId: prover_id,
        proofRaw: proof_raw,
        sectorId: sector_id,
        ticket,
        publicInputs: public_inputs,
        sectorSize: 'sector_size2_kib'
    });
    console.log("submitVerify", submitVerify)
}

main().catch((err) => {
    console.log(err)
    process.exit(1)
})
