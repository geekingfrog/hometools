use anyhow::{anyhow, Context};
use password_hash::{PasswordHashString, SaltString};
use std::{collections::HashMap, str::FromStr};

use crate::wol::MacAddress;
use toml;

#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) server_mac: MacAddress,
    /// for simplicity, only get a unique salt for every user (likely only one ever)
    pub(crate) salt: SaltString,
    pub(crate) users: HashMap<String, PasswordHashString>,
}

#[derive(Debug, serde::Deserialize)]
struct UserAuth {
    username: String,
    hashed_password: String,
}

#[derive(serde::Deserialize)]
struct TomlConfig {
    server_mac: String,
    salt: String,
    users: Vec<UserAuth>,
}

pub(crate) async fn read_config() -> anyhow::Result<Config> {
    let raw = tokio::fs::read_to_string("config.toml")
        .await
        .context("cannot read config at config.toml")?;
    let toml_config: TomlConfig = toml::from_str(&raw).context("cannot parse toml config")?;
    let server_mac = MacAddress::from_str(&toml_config.server_mac)
        .map_err(|_| anyhow!("invalid mac address {}", toml_config.server_mac))?;

    let users = toml_config
        .users
        .into_iter()
        .map(|auth| {
            let phc = PasswordHashString::new(&auth.hashed_password);
            phc.map(|phc| (auth.username, phc))
        })
        .collect::<password_hash::errors::Result<HashMap<_, _>>>()?;
    let salt = SaltString::from_b64(&toml_config.salt)?;

    Ok(Config {
        server_mac,
        users,
        salt,
    })
}
