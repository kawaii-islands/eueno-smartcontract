// @ts-ignore
import { SimulateCosmWasmClient } from '@terran-one/cw-simulate';
// @ts-ignore
import crypto from 'crypto';
// @ts-ignore
import path from 'path';
import { ContractClient } from '../contract/Contract.client';
import { InstantiateMsg } from '../contract/Contract.types';

import { setup, seal } from '../porep_app';

const filePath = path.resolve(__dirname, '..', '..', 'prover-node', 'file_2kiB.txt');
const wasmPath = path.resolve(__dirname, '..', '..', 'contract', 'artifacts', 'contract.wasm');
const senderAddress = 'orai1g4h64yjt0fvzv5v2j8tyfnpe5kmnetejvfgs7g';
const client = new SimulateCosmWasmClient({
  zkFeatures: true,
  chainId: 'Oraichain',
  bech32Prefix: 'orai'
});

describe('simple-flow', () => {
  let contract: ContractClient;

  beforeEach(async () => {
    const { contractAddress } = await client.deploy(senderAddress, wasmPath, {} as InstantiateMsg, 'porep-contract', 'auto');
    contract = new ContractClient(client, senderAddress, contractAddress);
  });

  it('verify-file-ok', async () => {
    const [porep_id, prover_id] = [crypto.randomBytes(32).toString('base64'), crypto.randomBytes(32).toString('base64')];
    const { setup_params, vk_raw } = setup({
      porep_id,
      api_version: 'V1_0_0',
      sector_size: 'sector_size2_kib'
    });

    console.log(setup_params, vk_raw);

    const res = await contract.setVerifierParams({ params: { setup_params, minimum_challenges: 1, vk: vk_raw }, sectorSize: 'sector_size2_kib' });
    console.log(JSON.stringify(res));
    const { proof_raw, public_inputs } = seal({
      // secret random
      prover_id,
      setup_params,
      file_path: filePath
    });

    console.log(proof_raw);

    const verifyRes = await contract.verifyProof({ apiVersion: 'V1_0_0', porepId: porep_id, proofRaw: proof_raw, publicInputs: public_inputs, sectorSize: 'sector_size2_kib' });

    expect(verifyRes).toBeTruthy();
  });
});
