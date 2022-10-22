#[macro_use]
extern crate log;

use ::hex::ToHex;
use actix_web::{get, web, App, HttpResponse, HttpServer};
use clap::Parser;

use core::ptr;
use secp256k1_sys::{
    types::{c_int, c_uchar, c_void, size_t},
    CPtr, SchnorrSigExtraParams,
};
use secp256k1_zkp::{
    constants::SCHNORR_SIGNATURE_SIZE, hashes::*, rand, schnorr::Signature as SchnorrSignature,
    All, KeyPair, Message, Secp256k1, SecretKey, Signing, XOnlyPublicKey as SchnorrPublicKey,
};
use secp256k1_zkp_5::rand::RngCore;
use std::io::{prelude::*, Cursor};

use serde::{Deserialize, Serialize};

use sled::IVec;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    str::FromStr,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use sibyls::{
    oracle::{oracle_queryable::messaging::OracleAnnouncementHash, DbValue, Oracle},
    Announcement, AssetPair, AssetPairInfo, Attestation, EventDescriptor, OracleConfig,
    OracleEvent,
};

mod error;
use error::SibylsError;

extern "C" fn constant_nonce_fn(
    nonce32: *mut c_uchar,
    _: *const c_uchar,
    _: size_t,
    _: *const c_uchar,
    _: *const c_uchar,
    _: *const c_uchar,
    _: size_t,
    data: *mut c_void,
) -> c_int {
    unsafe {
        ptr::copy_nonoverlapping(data as *const c_uchar, nonce32, 32);
    }
    1
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum SortOrder {
    Insertion,
    ReverseInsertion,
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Filters {
    sort_by: SortOrder,
    page: u32,
    asset_pair: AssetPair,
    maturation: String,
    outcome: Option<u64>,
}

impl Default for Filters {
    fn default() -> Self {
        Filters {
            sort_by: SortOrder::ReverseInsertion,
            page: 0,
            asset_pair: AssetPair::BTCUSD,
            maturation: "".to_string(),
            outcome: None,
        }
    }
}

#[derive(Serialize)]
struct ApiOracleEvent {
    event_id: String,
    uuid: String,
    asset_pair: AssetPair,
    suredbits_announcement: String,
    rust_announcement_json: String,
    rust_announcement: String,
    suredbits_attestation: Option<String>,
    rust_attestation_json: Option<String>,
    rust_attestation: Option<String>,
    maturation: String,
    outcome: Option<u64>,
}

fn parse_database_entry(
    asset_pair: AssetPair,
    (maturation, event): (IVec, IVec),
) -> ApiOracleEvent {
    let maturation = String::from_utf8_lossy(&maturation).to_string();
    let event: DbValue = serde_json::from_str(&String::from_utf8_lossy(&event)).unwrap();

    let mut announcement_cursor = Cursor::new(&event.3);
    let decoded_announcement =
        <dlc_messages::oracle_msgs::OracleAnnouncement as lightning::util::ser::Readable>::read(
            &mut announcement_cursor,
        )
        .unwrap();
    let decoded_ann_json = format!("{:?}", decoded_announcement);

    let db_att = event.4.clone();
    let decoded_att_json = match db_att {
        None => None,
        Some(att_vec) => {
            let mut attestation_cursor = Cursor::new(&att_vec);

            let att_obj = <dlc_messages::oracle_msgs::OracleAttestation as lightning::util::ser::Readable>::read(
                &mut attestation_cursor,
            )
            .ok();
            Some(format!("{:?}", att_obj.unwrap()))
        }
    };

    ApiOracleEvent {
        event_id: decoded_announcement.oracle_event.event_id.clone(),
        uuid: event.6,
        asset_pair,
        suredbits_announcement: event.1.encode_hex::<String>(),
        rust_announcement_json: decoded_ann_json,
        rust_announcement: event.3.encode_hex::<String>(),
        suredbits_attestation: event.2.map(|att| att.encode_hex::<String>()),
        rust_attestation_json: decoded_att_json,
        rust_attestation: event.4.map(|att| att.encode_hex::<String>()),
        maturation,
        outcome: event.5,
    }
}

pub fn build_announcement(
    keypair: &KeyPair,
    secp: &Secp256k1<All>,
    maturation: OffsetDateTime,
    event_id: String,
) -> Result<(Announcement, Vec<[u8; 32]>), secp256k1_zkp::UpstreamError> {
    let mut rng = rand::thread_rng();
    let num_digits = 10u16;
    let mut sk_nonces = Vec::with_capacity(num_digits.into());
    let mut nonces = Vec::with_capacity(num_digits.into());
    for _ in 0..num_digits {
        let mut sk_nonce = [0u8; 32];
        rng.fill_bytes(&mut sk_nonce);
        let oracle_r_kp = secp256k1_zkp::KeyPair::from_seckey_slice(secp, &sk_nonce)?;
        let nonce = SchnorrPublicKey::from_keypair(&oracle_r_kp);
        sk_nonces.push(sk_nonce);
        nonces.push(nonce);
    }

    let event_descriptor = EventDescriptor {
        base: 2,
        is_signed: false,
        unit: "BTCUSD".to_string(),
        precision: 0,
        num_digits,
    };

    let oracle_event = OracleEvent {
        nonces,
        maturation,
        event_descriptor: event_descriptor.clone(),
        event_id,
    };

    let ann = Announcement {
        signature: secp.sign_schnorr(
            &Message::from_hashed_data::<OracleAnnouncementHash>(&oracle_event.encode()),
            keypair,
        ),
        oracle_pubkey: keypair.public_key(),
        oracle_event,
    };
    Ok((ann, sk_nonces))
}

pub fn build_attestation(
    outstanding_sk_nonces: Vec<[u8; 32]>,
    keypair: &KeyPair,
    secp: &Secp256k1<All>,
    outcomes: Vec<String>,
) -> Attestation {
    let signatures = outcomes
        .iter()
        .zip(outstanding_sk_nonces.iter())
        .map(|(outcome, outstanding_sk_nonce)| {
            sign_schnorr_with_nonce(
                secp,
                &Message::from_hashed_data::<sha256::Hash>(
                    // &Message::from_hashed_data::<secp256k1_zkp_5::bitcoin_hashes::sha256::Hash>(
                    outcome.as_bytes(),
                ),
                keypair,
                outstanding_sk_nonce,
            )
        })
        .collect::<Vec<_>>();
    Attestation {
        oracle_pubkey: keypair.public_key(),
        signatures,
        outcomes,
    }
}

fn sign_schnorr_with_nonce<S: Signing>(
    secp: &Secp256k1<S>,
    msg: &Message,
    keypair: &KeyPair,
    nonce: &[u8; 32],
) -> SchnorrSignature {
    unsafe {
        let mut sig = [0u8; SCHNORR_SIGNATURE_SIZE];
        let nonce_params =
            SchnorrSigExtraParams::new(Some(constant_nonce_fn), nonce.as_c_ptr() as *const c_void);
        assert_eq!(
            1,
            secp256k1_sys::secp256k1_schnorrsig_sign_custom(
                *secp.ctx(),
                sig.as_mut_c_ptr(),
                msg.as_c_ptr(),
                msg.len(),
                keypair.as_ptr(),
                &nonce_params as *const SchnorrSigExtraParams
            )
        );

        SchnorrSignature::from_slice(&sig).unwrap()
    }
}

#[get("/create_event/{uuid}")]
async fn create_event(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /create_event/{}: {:#?}", path, filters);
    let uuid = path.to_string();
    let maturation = OffsetDateTime::parse(&filters.maturation, &Rfc3339)
        .map_err(SibylsError::DatetimeParseError)?;

    info!(
        "Creating event for uuid:{} and maturation_time :{}",
        uuid, maturation
    );

    let oracle = match oracles.get(&filters.asset_pair) {
        None => return Err(SibylsError::UnrecordedAssetPairError(filters.asset_pair).into()),
        Some(val) => val,
    };

    let (announcement_obj, outstanding_sk_nonces) = build_announcement(
        oracle.get_keypair(),
        oracle.get_secp(),
        maturation,
        uuid.clone(),
    )
    .unwrap();

    let response = format!(
        "creating oracle event (announcement only) with uuid {} and maturation {}",
        uuid, maturation
    );

    let db_value = DbValue(
        Some(outstanding_sk_nonces),
        announcement_obj.suredbits_encode(),
        None,
        announcement_obj.encode(),
        None,
        None,
        uuid.clone(),
    );

    oracle
        .event_database
        .insert(
            uuid.into_bytes(),
            serde_json::to_string(&db_value)?.into_bytes(),
        )
        .unwrap();

    Ok(HttpResponse::Ok().json(response))
}

#[get("/attest/{uuid}")]
async fn attest(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /announcement/{}: {:#?}", path, filters);
    let uuid = path.to_string();
    let outcome = &filters.outcome.unwrap();

    let oracle = match oracles.get(&filters.asset_pair) {
        None => return Err(SibylsError::UnrecordedAssetPairError(filters.asset_pair).into()),
        Some(val) => val,
    };

    if oracle.event_database.is_empty() {
        info!("no oracle events found");
        return Err(SibylsError::OracleEventNotFoundError(uuid).into());
    }

    info!("retrieving oracle event with maturation {}", path);
    let event_ivec = match oracle
        .event_database
        .get(path.as_bytes())
        .map_err(SibylsError::DatabaseError)?
    {
        Some(val) => val,
        None => return Err(SibylsError::OracleEventNotFoundError(uuid).into()),
    };

    let thing = parse_database_entry(filters.asset_pair, ((&**path).into(), event_ivec.clone()));
    let mut event: DbValue = serde_json::from_str(&String::from_utf8_lossy(&event_ivec)).unwrap();

    let outstanding_sk_nonces = event.clone().0.unwrap();

    let num_digits_to_sign = 10;
    // Here, we take the outcome of the DLC (0-10000), break it down into binary, break it into a vec of characters
    let outcomes = format!("{:0width$b}", outcome, width = num_digits_to_sign as usize)
        .chars()
        .map(|char| char.to_string())
        .collect::<Vec<_>>();

    let attestation = build_attestation(
        outstanding_sk_nonces,
        oracle.get_keypair(),
        &oracle.get_secp(),
        outcomes,
    );

    event.2 = Some(attestation.suredbits_encode());
    event.5 = Some(*outcome);
    event.4 = Some(attestation.encode());

    info!(
        "attesting with maturation {} and attestation {:#?}",
        path, attestation
    );

    let _insert_event = match oracle
        .event_database
        .insert(
            path.clone().as_bytes(),
            serde_json::to_string(&event)?.into_bytes(),
        )
        .map_err(SibylsError::DatabaseError)?
    {
        Some(val) => val,
        None => return Err(SibylsError::OracleEventNotFoundError(uuid).into()),
    };

    Ok(HttpResponse::Ok().json(thing))
}

#[get("/announcements")]
async fn announcements(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /announcements: {:#?}", filters);
    let oracle = match oracles.get(&filters.asset_pair) {
        None => return Err(SibylsError::UnrecordedAssetPairError(filters.asset_pair).into()),
        Some(val) => val,
    };

    if oracle.event_database.is_empty() {
        info!("no oracle events found");
        return Ok(HttpResponse::Ok().json(Vec::<ApiOracleEvent>::new()));
    }

    return Ok(HttpResponse::Ok().json(
        oracle
            .event_database
            .iter()
            .map(|result| parse_database_entry(filters.asset_pair, result.unwrap()))
            .collect::<Vec<_>>(),
    ));
}

#[get("/announcement/{uuid}")]
async fn get_announcement(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /announcement/{}: {:#?}", path, filters);
    let uuid = path.to_string();

    let oracle = match oracles.get(&filters.asset_pair) {
        None => return Err(SibylsError::UnrecordedAssetPairError(filters.asset_pair).into()),
        Some(val) => val,
    };

    if oracle.event_database.is_empty() {
        info!("no oracle events found");
        return Err(SibylsError::OracleEventNotFoundError(path.to_string()).into());
    }

    info!("retrieving oracle event with uuid {}", uuid);
    let event = match oracle
        .event_database
        .get(uuid.as_bytes())
        .map_err(SibylsError::DatabaseError)?
    {
        Some(val) => val,
        None => return Err(SibylsError::OracleEventNotFoundError(path.to_string()).into()),
    };
    Ok(HttpResponse::Ok().json(parse_database_entry(
        filters.asset_pair,
        ((&**path).into(), event),
    )))
}

#[get("/attestation/{rfc3339_time}")]
async fn get_attestation(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /attestation/{}: {:#?}", path, filters);
    let _ = OffsetDateTime::parse(&path, &Rfc3339).map_err(SibylsError::DatetimeParseError)?;

    let oracle = match oracles.get(&filters.asset_pair) {
        None => return Err(SibylsError::UnrecordedAssetPairError(filters.asset_pair).into()),
        Some(val) => val,
    };

    if oracle.event_database.is_empty() {
        info!("no oracle events found");
        return Err(SibylsError::OracleEventNotFoundError(path.to_string()).into());
    }

    info!("retrieving oracle event with maturation {}", path);
    let event = match oracle
        .event_database
        .get(path.as_bytes())
        .map_err(SibylsError::DatabaseError)?
    {
        Some(val) => val,
        None => return Err(SibylsError::OracleEventNotFoundError(path.to_string()).into()),
    };
    Ok(HttpResponse::Ok().json(parse_database_entry(
        filters.asset_pair,
        ((&**path).into(), event),
    )))
}

#[get("/config")]
async fn config(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /config");
    Ok(HttpResponse::Ok().json(
        oracles
            .values()
            .next()
            .expect("no asset pairs recorded")
            .oracle_config,
    ))
}

#[get("/publickey")]
async fn publickey() -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /publickey");
    let mut secret_key = String::new();
    let secp = Secp256k1::new();
    File::open("config/secret.key")?.read_to_string(&mut secret_key)?;
    secret_key.retain(|c| !c.is_whitespace());

    let secret_key = match SecretKey::from_str(&secret_key) {
        Ok(a) => (a),
        Err(_error) => return Err(SibylsError::SignatureError("path".to_string()).into()), //actix_web::Error(erro)
    };

    let keypair = KeyPair::from_secret_key(&secp, secret_key);
    Ok(HttpResponse::Ok().json(keypair.public_key().serialize().encode_hex::<String>()))
}

#[derive(Parser)]
/// Simple DLC oracle implementation
struct Args {
    /// Optional private key file; if not provided, one is generated
    #[clap(short, long, parse(from_os_str), value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    secret_key_file: Option<std::path::PathBuf>,

    /// Optional asset pair config file; if not provided, it is assumed to exist at "config/asset_pair.json"
    #[clap(short, long, parse(from_os_str), value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    asset_pair_config_file: Option<std::path::PathBuf>,

    /// Optional oracle config file; if not provided, it is assumed to exist at "config/oracle.json"
    #[clap(short, long, parse(from_os_str), value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    oracle_config_file: Option<std::path::PathBuf>,
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    let mut secret_key = String::new();
    let secp = Secp256k1::new();

    //TODO: this should only start with a key. If not present, should require a flag to create fresh
    let secret_key = match args.secret_key_file {
        None => {
            info!("no secret key file was found, generating secret key");
            let new_key = secp.generate_keypair(&mut rand::thread_rng()).0;
            let mut file = File::create("config/secret.key")?;
            file.write_all(new_key.display_secret().to_string().as_bytes())?;
            new_key
        }
        Some(path) => {
            info!(
                "reading secret key from {}",
                path.as_os_str().to_string_lossy()
            );
            File::open(path)?.read_to_string(&mut secret_key)?;
            secret_key.retain(|c| !c.is_whitespace());
            SecretKey::from_str(&secret_key)?
        }
    };
    let keypair = KeyPair::from_secret_key(&secp, secret_key);
    info!(
        "oracle keypair successfully generated, pubkey is {}",
        keypair.public_key().serialize().encode_hex::<String>()
    );

    let asset_pair_infos: Vec<AssetPairInfo> = match args.asset_pair_config_file {
        None => {
            info!("reading asset pair config from config/asset_pair.json");
            serde_json::from_str(&fs::read_to_string("config/asset_pair.json")?)?
        }
        Some(path) => {
            info!(
                "reading asset pair config from {}",
                path.as_os_str().to_string_lossy()
            );
            let mut asset_pair_info = String::new();
            File::open(path)?.read_to_string(&mut asset_pair_info)?;
            serde_json::from_str(&asset_pair_info)?
        }
    };
    info!(
        "asset pair config successfully read: {:#?}",
        asset_pair_infos
    );

    let oracle_config: OracleConfig = match args.oracle_config_file {
        None => {
            info!("reading oracle config from config/oracle.json");
            serde_json::from_str(&fs::read_to_string("config/oracle.json")?)?
        }
        Some(path) => {
            info!(
                "reading oracle config from {}",
                path.as_os_str().to_string_lossy()
            );
            let mut oracle_config = String::new();
            File::open(path)?.read_to_string(&mut oracle_config)?;
            serde_json::from_str(&oracle_config)?
        }
    };
    info!("oracle config successfully read: {:#?}", oracle_config);

    // setup event databases
    let oracles = asset_pair_infos
        .iter()
        .map(|asset_pair_info| asset_pair_info.asset_pair)
        .zip(asset_pair_infos.iter().cloned().map(|asset_pair_info| {
            let asset_pair = asset_pair_info.asset_pair;

            // create oracle
            info!("creating oracle for {}", asset_pair);
            let oracle = Oracle::new(oracle_config, keypair, secp.clone())?;

            Ok(oracle)
        }))
        .map(|(asset_pair, oracle)| oracle.map(|ok| (asset_pair, ok)))
        .collect::<anyhow::Result<HashMap<_, _>>>()?;

    // setup and run server
    info!("starting server");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(oracles.clone()))
            .service(
                web::scope("/v1")
                    .service(announcements)
                    .service(get_announcement)
                    .service(get_attestation)
                    .service(config)
                    .service(publickey)
                    .service(attest)
                    .service(create_event),
            )
    })
    .bind(("0.0.0.0", 8080))?
    // .bind(("54.198.187.245", 8080))? //TODO: Should we bind to only certain IPs for security?
    .run()
    .await?;

    Ok(())
}
