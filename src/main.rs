#[macro_use]
extern crate log;

use actix_web::{get, web, App, HttpResponse, HttpServer};
use clap::Parser;
use hex::ToHex;

use std::io::prelude::*;

use secp256k1_zkp::{
    rand, All, KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey as SchnorrPublicKey,
};
use secp256k1_zkp_5::rand::RngCore;

use serde::{Deserialize, Serialize};
use sled::IVec;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    str::FromStr,
};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use sibyls::{
    oracle::{
        oracle_scheduler::{self, messaging::OracleAnnouncementHash},
        pricefeeds::{Bitstamp, GateIo, Kraken, PriceFeed},
        DbValue, Oracle,
    },
    Announcement, AssetPair, AssetPairInfo, OracleConfig, OracleEvent,
};

mod error;
use error::SibylsError;

const PAGE_SIZE: u32 = 100;

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
}

impl Default for Filters {
    fn default() -> Self {
        Filters {
            sort_by: SortOrder::ReverseInsertion,
            page: 0,
            asset_pair: AssetPair::BTCUSD,
        }
    }
}

#[derive(Serialize)]
struct ApiOracleEvent {
    asset_pair: AssetPair,
    announcement: String,
    attestation: Option<String>,
    maturation: String,
    outcome: Option<u64>,
}

fn parse_database_entry(
    asset_pair: AssetPair,
    (maturation, event): (IVec, IVec),
) -> ApiOracleEvent {
    let maturation = String::from_utf8_lossy(&maturation).to_string();
    let event: DbValue = serde_json::from_str(&String::from_utf8_lossy(&event)).unwrap();
    ApiOracleEvent {
        asset_pair,
        announcement: event.1.encode_hex::<String>(),
        attestation: event.2.map(|att| att.encode_hex::<String>()),
        maturation,
        outcome: event.3,
    }
}

pub fn build_announcement(
    asset_pair_info: &AssetPairInfo,
    keypair: &KeyPair,
    secp: &Secp256k1<All>,
    maturation: OffsetDateTime,
) -> Result<(Announcement, Vec<[u8; 32]>), secp256k1_zkp::UpstreamError> {
    let mut rng = rand::thread_rng();
    let digits = asset_pair_info.event_descriptor.num_digits; // This is always going to be 5 or so, because that's the precision we will have in our Alice/Bob contract
    let mut sk_nonces = Vec::with_capacity(digits.into());
    let mut nonces = Vec::with_capacity(digits.into());
    for _ in 0..digits {
        let mut sk_nonce = [0u8; 32];
        rng.fill_bytes(&mut sk_nonce);
        let oracle_r_kp = secp256k1_zkp::KeyPair::from_seckey_slice(secp, &sk_nonce)?;
        let nonce = SchnorrPublicKey::from_keypair(&oracle_r_kp);
        sk_nonces.push(sk_nonce);
        nonces.push(nonce);
    }

    let oracle_event = OracleEvent {
        nonces,
        maturation,
        event_descriptor: asset_pair_info.event_descriptor.clone(),
    };

    Ok((
        Announcement {
            signature: secp.sign_schnorr(
                &Message::from_hashed_data::<OracleAnnouncementHash>(&oracle_event.encode()),
                keypair,
            ),
            oracle_pubkey: keypair.public_key(),
            oracle_event,
        },
        sk_nonces,
    ))
}

#[get("/create_event/{rfc3339_time}")]
async fn create_event(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /announcement/{}: {:#?}", path, filters);
    let maturation =
        OffsetDateTime::parse(&path, &Rfc3339).map_err(SibylsError::DatetimeParseError)?;

    let oracle = match oracles.get(&filters.asset_pair) {
        None => return Err(SibylsError::UnrecordedAssetPairError(filters.asset_pair).into()),
        Some(val) => val,
    };

    let build_announcement_response = build_announcement(
        &oracle.get_asset_pair_info(),
        oracle.get_keypair(),
        oracle.get_secp(),
        maturation,
    );
    let (announcement_obj, outstanding_sk_nonces) = match build_announcement_response {
        Ok((a, o)) => (a, o),
        Err(_error) => return Err(SibylsError::SignatureError(path.to_string()).into()), //actix_web::Error(erro)
    };

    info!(
        "creating oracle event (announcement only) with maturation {} and announcement {:#?}",
        maturation, announcement_obj
    );

    let db_value = DbValue(
        Some(outstanding_sk_nonces),
        announcement_obj.encode(),
        None,
        None,
    );

    oracle
        .event_database
        .insert(
            maturation.format(&Rfc3339).unwrap().into_bytes(),
            serde_json::to_string(&db_value)?.into_bytes(),
        )
        .unwrap();

    Ok(HttpResponse::Ok().json("Success"))
}

#[get("/attest/{rfc3339_time}")]
async fn attest(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /announcement/{}: {:#?}", path, filters);
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
    let event_ivec = match oracle
        .event_database
        .get(path.as_bytes())
        .map_err(SibylsError::DatabaseError)?
    {
        Some(val) => val,
        None => return Err(SibylsError::OracleEventNotFoundError(path.to_string()).into()),
    };

    let thing = parse_database_entry(filters.asset_pair, ((&**path).into(), event_ivec.clone()));
    let mut event: DbValue = serde_json::from_str(&String::from_utf8_lossy(&event_ivec)).unwrap();

    let outstanding_sk_nonces = event.clone().0.unwrap();

    let outcome_ratio = 5555;
    let num_digits_to_sign = 14;
    // Here, we take the outcome of the DLC (0-10000), break it down into binary, break it into a vec of characters
    let outcomes = format!(
        "{:0width$b}",
        outcome_ratio as u64,
        width = num_digits_to_sign as usize
    )
    .chars()
    .map(|char| char.to_string())
    .collect::<Vec<_>>();

    let attestation = sibyls::oracle::oracle_scheduler::build_attestation(
        outstanding_sk_nonces,
        oracle.get_keypair(),
        &oracle.get_secp(),
        outcomes,
    );

    println!("{:?}", attestation);
    println!("{:?}", attestation.encode());

    event.2 = Some(attestation.encode());
    event.3 = Some(5555);

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
        None => return Err(SibylsError::OracleEventNotFoundError(path.to_string()).into()),
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

    let start = filters.page * PAGE_SIZE;

    match filters.sort_by {
        SortOrder::Insertion => loop {
            let init_key = oracle
                .event_database
                .first()
                .map_err(SibylsError::DatabaseError)?
                .unwrap()
                .0;
            let start_key = OffsetDateTime::parse(&String::from_utf8_lossy(&init_key), &Rfc3339)
                .unwrap()
                + Duration::days(start.into());
            let end_key = start_key + Duration::days(PAGE_SIZE.into());
            let start_key = start_key.format(&Rfc3339).unwrap().into_bytes();
            let end_key = end_key.format(&Rfc3339).unwrap().into_bytes();
            if init_key
                == oracle
                    .event_database
                    .first()
                    .map_err(SibylsError::DatabaseError)?
                    .unwrap()
                    .0
            {
                // don't know if range can change while iterating due to another thread modifying
                info!(
                    "retrieving oracle events from {} to {}",
                    String::from_utf8_lossy(&start_key),
                    String::from_utf8_lossy(&end_key),
                );
                return Ok(HttpResponse::Ok().json(
                    oracle
                        .event_database
                        .range(start_key..end_key)
                        .map(|result| parse_database_entry(filters.asset_pair, result.unwrap()))
                        .collect::<Vec<_>>(),
                ));
            }
        },
        SortOrder::ReverseInsertion => loop {
            let init_key = oracle
                .event_database
                .last()
                .map_err(SibylsError::DatabaseError)?
                .unwrap()
                .0;
            let end_key = OffsetDateTime::parse(&String::from_utf8_lossy(&init_key), &Rfc3339)
                .unwrap()
                - Duration::days(start.into());
            let start_key = end_key - Duration::days(PAGE_SIZE.into());
            let start_key = start_key.format(&Rfc3339).unwrap().into_bytes();
            let end_key = end_key.format(&Rfc3339).unwrap().into_bytes();
            if init_key
                == oracle
                    .event_database
                    .last()
                    .map_err(SibylsError::DatabaseError)?
                    .unwrap()
                    .0
            {
                // don't know if range can change while iterating due to another thread modifying
                info!(
                    "retrieving oracle events from {} to {}",
                    String::from_utf8_lossy(&start_key),
                    String::from_utf8_lossy(&end_key),
                );
                return Ok(HttpResponse::Ok().json(
                    oracle
                        .event_database
                        .range(start_key..end_key)
                        .map(|result| parse_database_entry(filters.asset_pair, result.unwrap()))
                        .collect::<Vec<_>>(),
                ));
            }
        },
    }
}

#[get("/announcement/{rfc3339_time}")]
async fn announcement(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /announcement/{}: {:#?}", path, filters);
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
            let oracle = Oracle::new(oracle_config, asset_pair_info, keypair, secp.clone())?;

            // pricefeed retreival
            info!("creating pricefeeds for {}", asset_pair);
            let pricefeeds: Vec<Box<dyn PriceFeed + Send + Sync>> = vec![
                Box::new(Bitstamp {}),
                Box::new(GateIo {}),
                Box::new(Kraken {}),
            ];

            info!("scheduling oracle events for {}", asset_pair);
            // schedule oracle events (announcements/attestations)
            oracle_scheduler::init(oracle.clone(), secp.clone(), pricefeeds)?;

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
                    .service(announcement)
                    .service(config)
                    .service(attest)
                    .service(create_event),
            )
    })
    .bind(("0.0.0.0", 8080))?
    // .bind(("54.198.187.245", 8080))?
    .run()
    .await?;

    Ok(())
}
