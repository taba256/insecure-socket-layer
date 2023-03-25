use rsa::RsaPrivateKey;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

pub struct ServerConfig {
    pub certs: Vec<Vec<u8>>,
    pub private_key: RsaPrivateKey,
    pub sessions: RwLock<HashMap<Vec<u8>, ()>>,
}
impl ServerConfig {
    pub fn clone(self: &Arc<Self>) -> Arc<Self> {
        Arc::clone(self)
    }
}

#[derive(Default)]
pub struct ServerConfigBuilder {
    certs: Vec<Vec<u8>>,
    private_key: Option<RsaPrivateKey>,
}
impl ServerConfigBuilder {
    pub fn new() -> Self {
        Self {
            certs: Vec::new(),
            private_key: None,
        }
    }
    pub fn add_cert(mut self, cert: &[u8]) -> Self {
        self.certs.push(cert.to_vec());
        self
    }
    pub fn set_private_key(mut self, key: RsaPrivateKey) -> Self {
        self.private_key = Some(key);
        self
    }
    pub fn set_private_key_pkcs1_pem(mut self, key: &str) -> Self {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        self.private_key = Some(RsaPrivateKey::from_pkcs1_pem(key).unwrap());
        self
    }
    pub fn set_private_key_pkcs1_der(mut self, key: &[u8]) -> Self {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        self.private_key = Some(RsaPrivateKey::from_pkcs1_der(key).unwrap());
        self
    }
    pub fn set_private_key_pkcs8_pem(mut self, key: &str) -> Self {
        use rsa::pkcs8::DecodePrivateKey;
        self.private_key = Some(RsaPrivateKey::from_pkcs8_pem(key).unwrap());
        self
    }
    pub fn set_private_key_pkcs8_der(mut self, key: &[u8]) -> Self {
        use rsa::pkcs8::DecodePrivateKey;
        self.private_key = Some(RsaPrivateKey::from_pkcs8_der(key).unwrap());
        self
    }
    pub fn build(self) -> Arc<ServerConfig> {
        Arc::new(ServerConfig {
            certs: self.certs,
            sessions: RwLock::default(),
            private_key: self.private_key.unwrap(),
        })
    }
}
