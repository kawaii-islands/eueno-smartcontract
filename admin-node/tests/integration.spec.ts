import {SimulateCosmWasmClient} from '@terran-one/cw-simulate';
import crypto from 'crypto';
import path from 'path';
import {ContractClient} from '../../contract/build/Contract.client';
import {InstantiateMsg} from '../../contract/build/Contract.types';

import {setup, seal} from '../porep_app';

const filePath = path.resolve(__dirname, '..', '..', 'contract/script', 'test.txt');
const wasmPath = path.resolve(__dirname, '..', '..', 'contract', 'artifacts', 'contract.wasm');
const senderAddress = 'orai1nw5dvqa6j649aaf2hdgqfqa47lpmv77yyu5ulw';
const client = new SimulateCosmWasmClient({
    zkFeatures: true,
    chainId: 'Oraichain',
    bech32Prefix: 'orai'
});

describe('simple-flow', () => {
    let contract: ContractClient;

    beforeEach(async () => {
        const {contractAddress} = await client.deploy(senderAddress, wasmPath, {} as InstantiateMsg, 'porep-contract', 'auto');
        contract = new ContractClient(client, senderAddress, contractAddress);
    });

    it('verify-file-ok', async () => {
        // const porep_id = crypto.randomBytes(32).toString('base64')
        // const prover_id = Buffer.from("ab5a507792a559a63a30ff09091c267c454c563c3c6c88dd7c4785f0c63eaadc", "hex").toString("base64")
        // console.log("porep_id", porep_id)
        // console.log("prover_id", prover_id)

        const porep_id = "66z5mSlp7IIEcrHMxnzkG7TBHZRphpbw6m1Y/x63xm4="
        const prover_id = Buffer.from("ab5a507792a559a63a30ff09091c267c454c563c3c6c88dd7c4785f0c63eaadc", "hex").toString("base64")
        const sector_id = 1
        const ticket = "5JPQJmEEv48MrF0uMLd4YZMc7FJklqOBLGsAs/+qGZA="

        console.log("porep_id", porep_id)
        console.log("prover_id", prover_id)
        console.log("sector_id", sector_id)
        console.log("ticket", ticket)

        const {setup_params, vk_raw} = setup({
            porep_id,
            api_version: 'V1_0_0',
            sector_size: 'sector_size2_kib'
        });

        let res = await contract.setVerifierParams({
            params: {setup_params, minimum_challenges: 1, vk: vk_raw},
            sectorSize: 'sector_size2_kib',
            duration: 12312
        });

        console.log("set verify params", res)
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

        let submitVerify = await contract.submitProof({
            apiVersion: 'V1_0_0',
            porepId: porep_id,
            proverId: prover_id,
            proofRaw: proof_raw,
            sectorId: sector_id,
            ticket,
            publicInputs: public_inputs,
            sectorSize: 'sector_size2_kib'
        });
        console.log("submitVerify turn 1", submitVerify)

        // // expect(verifyRes).toBeTruthy();
        // let listUser = await contract.queryListUser({limit: 10})
        // console.log("reward", listUser[0])
        // let reward = await contract.queryUserReward({user: listUser[0].toString()})
        // console.log(reward)
        //
        // res = await contract.setVerifierParams({
        //     params: {setup_params, minimum_challenges: 1, vk: vk_raw},
        //     sectorSize: 'sector_size2_kib',
        //     duration: 12312
        // });
        //
        //
        // submitVerify = await contract.submitProof({
        //     apiVersion: 'V1_0_0',
        //     porepId: porep_id,
        //     proverId: prover_id,
        //     proofRaw: proof_raw,
        //     sectorId: sector_id,
        //     ticket,
        //     publicInputs: public_inputs,
        //     sectorSize: 'sector_size2_kib'
        // });
        //
        // console.log("submitVerify turn 2", submitVerify)
    });
});
