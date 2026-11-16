//! The `Broker` trait the proxy uses to obtain credential values. The proxy holds it as
//! `Arc<dyn Broker>`, so a different store can replace `FileStore` without touching the
//! pipeline.

use crate::store::{FileStore, SecretBytes, StoreErr};

pub trait Broker: Send + Sync {
    /// Return the current value for `source`, a reference such as `k8s:<secret>:<key>`.
    fn credential(&self, source: &str) -> Result<SecretBytes, StoreErr>;
}

impl Broker for FileStore {
    fn credential(&self, source: &str) -> Result<SecretBytes, StoreErr> {
        self.read(source)
    }
}
