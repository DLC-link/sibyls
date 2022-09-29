use crate::{AssetPairInfo, OracleConfig};
use log::info;
use secp256k1_zkp::All;
use secp256k1_zkp::KeyPair;
use secp256k1_zkp::Secp256k1;
use serde::{Deserialize, Serialize};
use sled::{Config, Db};

mod error;
pub use error::OracleError;
pub use error::Result;

#[derive(Clone, Deserialize, Serialize)]
// outstanding_sk_nonces?, announcement, attetstation?, outcome?
pub struct DbValue(
    pub Option<Vec<[u8; 32]>>,
    pub Vec<u8>,
    pub Option<Vec<u8>>,
    pub Option<u64>,
);

#[derive(Clone)]
pub struct Oracle {
    pub oracle_config: OracleConfig,
    asset_pair_info: AssetPairInfo,
    pub event_database: Db,
    keypair: KeyPair,
    secp: Secp256k1<All>,
}

impl Oracle {
    pub fn new(
        oracle_config: OracleConfig,
        asset_pair_info: AssetPairInfo,
        keypair: KeyPair,
        secp: Secp256k1<All>,
    ) -> Result<Oracle> {
        if !oracle_config.announcement_offset.is_positive() {
            return Err(OracleError::InvalidAnnouncementTimeError(
                oracle_config.announcement_offset,
            ));
        }

        // setup event database
        let path = format!("events/{}", asset_pair_info.asset_pair);
        info!("creating sled at {}", path);
        // let event_database = sled::open(path)?;
        let event_database = Config::new()
            .path(path)
            .cache_capacity(128 * 1024 * 1024)
            .open()?;

        Ok(Oracle {
            oracle_config,
            asset_pair_info,
            event_database,
            keypair,
            secp,
        })
    }

    pub fn get_keypair(&self) -> &KeyPair {
        &self.keypair
    }
    pub fn get_secp(&self) -> &Secp256k1<All> {
        &self.secp
    }
    pub fn get_asset_pair_info(&self) -> &AssetPairInfo {
        &self.asset_pair_info
    }
}

pub mod oracle_scheduler;
pub use oracle_scheduler::messaging::EventDescriptor;

pub mod pricefeeds;
