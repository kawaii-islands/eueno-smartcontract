use ark_serialize::CanonicalSerialize;
use base64::{engine::general_purpose, Engine as _};
use contract_auxiliaries::{
    deserializer::{deserialize_proof, deserialize_verifying_key},
    drg::stacked::{challenges::LayerChallenges as VerifierLayerChallenges, VerifierSetupParams},
    utils::ApiVersion as VerifierApiVersion,
};
use converter::serializer::{serialize_proof, serialize_verifying_key};
use node_bindgen::{
    core::val::{JsEnv, JsObject},
    core::{JSValue, NjError},
    derive::node_bindgen,
    sys::napi_value,
};
use proofs_core::{api_version::ApiVersion, merkle::MerkleTreeTrait, sector::SectorId};
use rand::{rngs::ThreadRng, thread_rng, Rng};
use seal::*;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[inline]
fn from_base64(data: &String) -> [u8; 32] {
    let mut bytes = general_purpose::STANDARD.decode(data).unwrap();
    bytes.resize(32, 0);
    let bytes: [u8; 32] = bytes.try_into().unwrap();
    return bytes;
}

enum SupportedSectorSize {
    SectorSize2Kib,
    SectorSize4Kib,
    SectorSize16Kib,
    SectorSize32Kib,
    SectorSize8Mib,
    SectorSize16Mib,
    SectorSize512Mib,
    SectorSize1Gib,
    SectorSize32Gib,
    SectorSize64Gib,
}

impl SupportedSectorSize {
    fn from_str(value: &str) -> SupportedSectorSize {
        match value {
            "sector_size2_kib" => SupportedSectorSize::SectorSize2Kib,
            "sector_size4_kib" => SupportedSectorSize::SectorSize4Kib,
            "sector_size16_kib" => SupportedSectorSize::SectorSize16Kib,
            "sector_size32_kib" => SupportedSectorSize::SectorSize32Kib,
            "sector_size8_mib" => SupportedSectorSize::SectorSize8Mib,
            "sector_size16_mib" => SupportedSectorSize::SectorSize16Mib,
            "sector_size512_mib" => SupportedSectorSize::SectorSize512Mib,
            "sector_size1_gib" => SupportedSectorSize::SectorSize1Gib,
            "sector_size32_gib" => SupportedSectorSize::SectorSize32Gib,
            "sector_size64_gib" => SupportedSectorSize::SectorSize64Gib,
            _ => panic!("Unknown value: {}", value),
        }
    }
}

struct Setup {
    sector_size: SupportedSectorSize,
    porep_id: String,
    api_version: String,
}

impl JSValue<'_> for Setup {
    fn convert_to_rust(env: &JsEnv, js_value: napi_value) -> Result<Self, NjError> {
        if let Ok(js_obj) = env.convert_to_rust::<JsObject>(js_value) {
            let json = Self {
                sector_size: SupportedSectorSize::from_str(
                    &js_obj
                        .get_property("sector_size")?
                        .unwrap()
                        .as_value::<String>()
                        .unwrap(),
                ),
                api_version: js_obj
                    .get_property("api_version")?
                    .unwrap()
                    .as_value::<String>()
                    .unwrap(),
                porep_id: js_obj
                    .get_property("porep_id")?
                    .unwrap()
                    .as_value::<String>()
                    .unwrap(),
            };
            Ok(json)
        } else {
            Err(NjError::Other("not valid format".to_owned()))
        }
    }
}

struct Seal {
    // setup
    porep_id: String,
    api_version: String,

    // public input
    file_path: String,
    prover_id: String,
    sector_id: u64,       //
    ticket: String,       // base64
    seed: Option<String>, // base64,
}

impl JSValue<'_> for Seal {
    fn convert_to_rust(env: &JsEnv, js_value: napi_value) -> Result<Self, NjError> {
        if let Ok(js_obj) = env.convert_to_rust::<JsObject>(js_value) {
            let json = Self {
                api_version: js_obj
                    .get_property("api_version")?
                    .unwrap()
                    .as_value::<String>()
                    .unwrap(),
                porep_id: js_obj
                    .get_property("porep_id")?
                    .unwrap()
                    .as_value::<String>()
                    .unwrap(),
                file_path: js_obj
                    .get_property("file_path")?
                    .unwrap()
                    .as_value::<String>()
                    .unwrap(),
                prover_id: js_obj
                    .get_property("prover_id")?
                    .unwrap()
                    .as_value::<String>()
                    .unwrap(),
                sector_id: js_obj
                    .get_property("sector_id")?
                    .unwrap()
                    .as_value::<i64>()
                    .unwrap() as u64,
                ticket: js_obj
                    .get_property("ticket")?
                    .unwrap()
                    .as_value::<String>()
                    .unwrap(),
                seed: js_obj
                    .get_property("seed")?
                    .map(|v| v.as_value::<String>().unwrap()),
            };
            Ok(json)
        } else {
            Err(NjError::Other("not valid format".to_owned()))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct SealResult<T: Serialize + ?Sized> {
    pub proof_raw: String,
    pub public_inputs: T,
}

fn process_seal_and_unseal<T: 'static + MerkleTreeTrait>(args: &Seal) -> String {
    let file_path = Path::new(&args.file_path);

    let sector_size = get_file_size(file_path);

    let mut rng = thread_rng();
    let porep_id = from_base64(&args.porep_id);
    let prover_id = from_base64(&args.prover_id);
    let ticket = from_base64(&args.ticket);

    let seed = match &args.seed {
        Some(id) => from_base64(id),
        None => rng.gen(),
    };

    let api_version = match args.api_version.as_str() {
        "V1_0_0" => ApiVersion::V1_0_0,
        _ => ApiVersion::V1_1_0,
    };

    let (pre_commit_output, commit_output) = seal::<ThreadRng, T>(
        &mut rng,
        sector_size,
        prover_id,
        &porep_id,
        &ticket,
        &seed,
        SectorId::from(args.sector_id),
        api_version,
        file_path,
    )
    .expect("failed to seal file");

    let config = porep_config(sector_size, porep_id, api_version);
    let (public_inputs, proofs) = generate_proof_and_public_inputs::<T, _>(
        &config,
        pre_commit_output.comm_r,
        pre_commit_output.comm_d,
        prover_id,
        args.sector_id.into(),
        ticket,
        seed,
        commit_output.proof.as_slice(),
        Some(&mut rng),
    )
    .expect("failed to generate proof and public inputs");

    // convert bellperson to ark-groth16
    let proof = deserialize_proof(&serialize_proof(&proofs[0])).unwrap();
    let mut proof_raw = vec![];
    proof
        .serialize(&mut proof_raw)
        .expect("failed to serialize proof");

    let result = SealResult {
        proof_raw: general_purpose::STANDARD.encode(proof_raw),
        public_inputs,
    };

    serde_json::to_string(&result).unwrap_or_default()
}

fn process_setup<T: 'static + MerkleTreeTrait>(args: &Setup) -> String {
    let mut rng = thread_rng();
    let api_version = match args.api_version.as_str() {
        "V1_0_0" => ApiVersion::V1_0_0,
        _ => ApiVersion::V1_1_0,
    };
    let porep_id = from_base64(&args.porep_id);

    let sector_size = match args.sector_size {
        SupportedSectorSize::SectorSize2Kib => SECTOR_SIZE_2_KIB,
        SupportedSectorSize::SectorSize4Kib => SECTOR_SIZE_4_KIB,
        SupportedSectorSize::SectorSize16Kib => SECTOR_SIZE_16_KIB,
        SupportedSectorSize::SectorSize32Kib => SECTOR_SIZE_32_KIB,
        SupportedSectorSize::SectorSize8Mib => SECTOR_SIZE_8_MIB,
        SupportedSectorSize::SectorSize16Mib => SECTOR_SIZE_16_MIB,
        SupportedSectorSize::SectorSize512Mib => SECTOR_SIZE_512_MIB,
        SupportedSectorSize::SectorSize1Gib => SECTOR_SIZE_1_GIB,
        SupportedSectorSize::SectorSize32Gib => SECTOR_SIZE_32_GIB,
        SupportedSectorSize::SectorSize64Gib => SECTOR_SIZE_64_GIB,
    };
    let config = porep_config(sector_size, porep_id, api_version);
    let (compound_setup_params, verifying_key, challenge_requirements) =
        generate_setup_params::<T, _>(&config, Some(&mut rng)).unwrap();

    let vanilla_params = compound_setup_params.vanilla_params;
    let verifier_setup_params = VerifierSetupParams {
        nodes: vanilla_params.nodes as u64,
        degree: vanilla_params.degree as u64,
        expansion_degree: vanilla_params.expansion_degree as u64,
        porep_id: vanilla_params.porep_id,
        layer_challenges: VerifierLayerChallenges::new(
            vanilla_params.layer_challenges.layers(),
            vanilla_params.layer_challenges.challenges_count_all(),
        ),
        api_version: match vanilla_params.api_version {
            ApiVersion::V1_0_0 => VerifierApiVersion::V1_0_0,
            ApiVersion::V1_1_0 => VerifierApiVersion::V1_1_0,
        },
    };

    // convert bellperson to ark-groth16
    let vk = deserialize_verifying_key(&serialize_verifying_key(&verifying_key)).unwrap();
    let mut vk_raw: Vec<u8> = vec![];
    vk.serialize(&mut vk_raw).unwrap();

    let result = SetupResult {
        setup_params: verifier_setup_params,
        vk_raw: general_purpose::STANDARD.encode(vk_raw),
        minimum_challenges: challenge_requirements.minimum_challenges as u64,
    };

    serde_json::to_string(&result).unwrap_or_default()
}

fn get_file_size(path: &Path) -> u64 {
    let metadata = fs::metadata(path).expect("failed to fetch file's metadata");
    let size = metadata.len();
    match size {
        x if x <= SECTOR_SIZE_2_KIB => SECTOR_SIZE_2_KIB,
        x if x <= SECTOR_SIZE_4_KIB => SECTOR_SIZE_4_KIB,
        x if x <= SECTOR_SIZE_16_KIB => SECTOR_SIZE_16_KIB,
        x if x <= SECTOR_SIZE_32_KIB => SECTOR_SIZE_32_KIB,
        x if x <= SECTOR_SIZE_8_MIB => SECTOR_SIZE_8_MIB,
        x if x <= SECTOR_SIZE_16_MIB => SECTOR_SIZE_16_MIB,
        x if x <= SECTOR_SIZE_512_MIB => SECTOR_SIZE_512_MIB,
        x if x <= SECTOR_SIZE_1_GIB => SECTOR_SIZE_1_GIB,
        x if x <= SECTOR_SIZE_32_GIB => SECTOR_SIZE_32_GIB,
        x if x <= SECTOR_SIZE_64_GIB => SECTOR_SIZE_64_GIB,
        _ => panic!("file is too large (maximum supported size: 64GiB)"),
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct SetupResult {
    pub setup_params: VerifierSetupParams,
    pub vk_raw: String,
    pub minimum_challenges: u64,
}

#[node_bindgen]
fn setup(args: Setup) -> String {
    match args.sector_size {
        SupportedSectorSize::SectorSize2Kib => process_setup::<SectorShape2KiB>(&args),
        SupportedSectorSize::SectorSize4Kib => process_setup::<SectorShape4KiB>(&args),
        SupportedSectorSize::SectorSize16Kib => process_setup::<SectorShape16KiB>(&args),
        SupportedSectorSize::SectorSize32Kib => process_setup::<SectorShape32KiB>(&args),
        SupportedSectorSize::SectorSize8Mib => process_setup::<SectorShape8MiB>(&args),
        SupportedSectorSize::SectorSize16Mib => process_setup::<SectorShape16MiB>(&args),
        SupportedSectorSize::SectorSize512Mib => process_setup::<SectorShape512MiB>(&args),
        SupportedSectorSize::SectorSize1Gib => process_setup::<SectorShape1GiB>(&args),
        SupportedSectorSize::SectorSize32Gib => process_setup::<SectorShape32GiB>(&args),
        SupportedSectorSize::SectorSize64Gib => process_setup::<SectorShape64GiB>(&args),
    }
}

#[node_bindgen]
fn seal(args: Seal) -> String {
    let file_path = Path::new(&args.file_path);

    let sector_size = get_file_size(file_path);

    match sector_size {
        SECTOR_SIZE_2_KIB => process_seal_and_unseal::<SectorShape2KiB>(&args),
        SECTOR_SIZE_4_KIB => process_seal_and_unseal::<SectorShape4KiB>(&args),
        SECTOR_SIZE_16_KIB => process_seal_and_unseal::<SectorShape16KiB>(&args),
        SECTOR_SIZE_32_KIB => process_seal_and_unseal::<SectorShape32KiB>(&args),
        SECTOR_SIZE_8_MIB => process_seal_and_unseal::<SectorShape8MiB>(&args),
        SECTOR_SIZE_16_MIB => process_seal_and_unseal::<SectorShape16MiB>(&args),
        SECTOR_SIZE_512_MIB => process_seal_and_unseal::<SectorShape512MiB>(&args),
        SECTOR_SIZE_1_GIB => process_seal_and_unseal::<SectorShape1GiB>(&args),
        SECTOR_SIZE_32_GIB => process_seal_and_unseal::<SectorShape32GiB>(&args),
        SECTOR_SIZE_64_GIB => process_seal_and_unseal::<SectorShape64GiB>(&args),
        _ => panic!("unexpected sector size"),
    }
}