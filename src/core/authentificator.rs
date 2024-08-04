use crate::core::config::Config;

#[derive(Clone)]
pub struct Authenticator;

impl From<&Config> for Authenticator {
    fn from(value: &Config) -> Self {
        Self
    }
}

impl Authenticator {
    pub fn auth(&self, password: &str) -> bool {
        true
    }

    pub fn record(&self, password: &str, download: usize, upload: usize) {}
}
