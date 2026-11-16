//! The `Broker` trait the proxy calls, and the in-process implementation
//! (Q2-A): session plane plus file store. No network, no resolve endpoint.

use crate::plane::SessionPlane;
use crate::store::{Secret, Store};
use ap_core::{Code, Policy};
use std::sync::Arc;

/// What admission learned about a surrogate: which session it belongs to, and
/// which of the session's credentials can be used on the requested route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub session: String,
    pub generation: u64,
    /// Credentials bound to the session whose route set contains the route.
    pub credentials: Vec<String>,
}

/// The two questions the proxy asks per request, in pipeline order: is this
/// surrogate live for this route (step 5), and then what is the credential
/// value (step 7). `policy` is the snapshot the request is being judged
/// against, so one request sees one snapshot.
pub trait Broker: Send + Sync {
    /// `surrogate_unknown | _revoked | _expired | _wrong_caller | _wrong_route`.
    fn admit(
        &self,
        surrogate_sha256: &[u8; 32],
        route: &str,
        policy: &Policy,
    ) -> Result<Binding, Code>;

    /// `broker_unavailable` when the store cannot produce the value now.
    fn secret(&self, credential: &str, policy: &Policy) -> Result<Arc<Secret>, Code>;
}

pub struct LocalBroker {
    plane: Arc<SessionPlane>,
    store: Arc<dyn Store>,
}

impl LocalBroker {
    pub fn new(plane: Arc<SessionPlane>, store: Arc<dyn Store>) -> LocalBroker {
        LocalBroker { plane, store }
    }

    pub fn plane(&self) -> &Arc<SessionPlane> {
        &self.plane
    }
}

impl Broker for LocalBroker {
    fn admit(
        &self,
        surrogate_sha256: &[u8; 32],
        route: &str,
        policy: &Policy,
    ) -> Result<Binding, Code> {
        let view = self.plane.lookup(surrogate_sha256)?;
        // A policy that now names another identity does not own this session.
        if view.identity != policy.identity() {
            return Err(Code::SurrogateWrongCaller);
        }
        let usable: Vec<String> = view
            .credentials
            .into_iter()
            .filter(|id| {
                policy
                    .credential(id)
                    .is_some_and(|c| c.routes.iter().any(|r| r == route))
            })
            .collect();
        if usable.is_empty() {
            return Err(Code::SurrogateWrongRoute);
        }
        Ok(Binding {
            session: view.session,
            generation: view.generation,
            credentials: usable,
        })
    }

    fn secret(&self, credential: &str, policy: &Policy) -> Result<Arc<Secret>, Code> {
        let c = policy
            .credential(credential)
            .ok_or(Code::BrokerUnavailable)?;
        self.store
            .resolve(&c.source)
            .map_err(|_| Code::BrokerUnavailable)
    }
}
