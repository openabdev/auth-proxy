//! Shared state of one proxy process.

use crate::audit::Audit;
use ap_broker::{LocalBroker, SessionPlane};
use ap_core::PolicyStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct App {
    pub policy: PolicyStore,
    pub broker: LocalBroker,
    pub plane: Arc<SessionPlane>,
    pub client: reqwest::Client,
    /// Exact `Host` values the agent listener accepts.
    pub authorities: Vec<String>,
    pub max_body: u64,
    pub audit: Audit,
    warned: Mutex<HashMap<&'static str, Instant>>,
}

const WARN_EVERY: Duration = Duration::from_secs(30);

impl App {
    pub fn new(
        policy: PolicyStore,
        broker: LocalBroker,
        client: reqwest::Client,
        authorities: Vec<String>,
        max_body: u64,
    ) -> App {
        let plane = broker.plane().clone();
        App {
            policy,
            broker,
            plane,
            client,
            authorities,
            max_body,
            audit: Audit::default(),
            warned: Mutex::new(HashMap::new()),
        }
    }

    /// An operator message on stderr, at most once per `WARN_EVERY` per key.
    /// Callers pass fixed text or the policy loader's own message; never
    /// anything taken from a request.
    pub fn warn_limited(&self, key: &'static str, msg: &str) {
        let mut w = self.warned.lock().unwrap();
        let due = w.get(key).is_none_or(|t| t.elapsed() >= WARN_EVERY);
        if due {
            w.insert(key, Instant::now());
            eprintln!("auth-proxy: {msg}");
        }
    }
}
