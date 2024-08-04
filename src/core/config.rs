use std::{collections::HashMap, fs::File, io::BufReader, net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;
use tracing::Level;

const EVP_MAX_MD_SIZE: usize = 64;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub run_type: RunType,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub target_addr: SocketAddr,
    #[serde(default)]
    pub password: HashMap<String, String>,
    #[serde(default)]
    pub udp_timeout: usize,
    #[serde(with = "log_level", default = "default_log_level")]
    pub log_level: Level,
    #[serde(default)]
    pub ssl_config: SSLConfig,
    #[serde(default)]
    pub tcp_config: TcpConfig,
}

fn default_log_level() -> Level {
    Level::DEBUG
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Serialization failed: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Failed to open file: {0}")]
    CouldNotOpenFile(#[from] std::io::Error),
}
mod log_level {
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serializer};
    use tracing::Level;

    pub fn serialize<S>(v: &Level, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(v.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Level, D::Error>
    where
        D: Deserializer<'de>,
    {
        Level::from_str(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl Config {
    pub fn sip003(&self) -> bool {
        true
    }

    pub fn sha224(message: &str) -> String {
        let mut hasher = sha2::Sha224::default();
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();

        let mut hex_hash = String::with_capacity((EVP_MAX_MD_SIZE << 1) + 1);
        for byte in hash.iter() {
            hex_hash.push_str(&format!("{:02x}", byte));
        }

        hex_hash
    }

    fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        serde_json::from_reader(reader).map_err(Into::into)
    }
    //void populate(const std::string &JSON);
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SSLConfig {
    pub verify: bool,
    pub verify_hostname: bool,
    pub cert: String,
    pub key: String,
    //pub key_password: String,
    pub cipher: String,
    pub cipher_tls13: String,
    pub prefer_server_cipher: bool,
    pub sni: String,
    pub alpn: String,
    pub alpn_port_override: HashMap<String, u16>,
    pub reuse_session: bool,
    pub session_ticket: bool,
    pub session_timeout: usize,
    pub plain_http_response: String,
    pub curves: Vec<String>,
    //pub dhparam: String,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TcpConfig {
    pub prefer_ipv4: bool,
    pub no_delay: bool,
    pub keep_alive: bool,
    pub reuse_port: bool,
    //pub fast_open: bool,
    //pub fast_open_qlen: usize,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum RunType {
    #[default]
    Server,
    Client,
    Forward,
    NAT,
}
