//! The `Broker` trait the proxy calls, and the in-process implementation
//! (Q2-A): session plane plus file store. No network, no resolve endpoint.

use crate::plane::SessionPlane;
use crate::registry::SessionView;
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

/// Session id the interim static session reports to the audit log.
pub const INTERIM_SESSION: &str = "interim-static";

/// INTERIM Q1-A path: the one session of a pod, fixed at proxy start. It has no
/// lease, no absolute TTL and no authority; nothing on the session plane can
/// register, renew, resync or revoke it. It ends only when the proxy process
/// does (pod deletion or restart). The owner accepted that there is no
/// per-session revocation on this path (decision record, Q1).
struct InterimSession {
    hash: [u8; 32],
    identity: String,
    credentials: Vec<String>,
}

pub struct LocalBroker {
    plane: Arc<SessionPlane>,
    store: Arc<dyn Store>,
    interim: Option<InterimSession>,
}

impl LocalBroker {
    pub fn new(plane: Arc<SessionPlane>, store: Arc<dyn Store>) -> LocalBroker {
        LocalBroker {
            plane,
            store,
            interim: None,
        }
    }

    /// INTERIM Q1-A: also admit one fixed surrogate (by `sha256`) as a session of
    /// `identity` bound to `credentials`, for the life of this broker. The Q1-B
    /// session machinery is untouched: this is a separate admission branch.
    pub fn with_interim_static_session(
        mut self,
        surrogate_sha256: [u8; 32],
        identity: &str,
        credentials: Vec<String>,
    ) -> LocalBroker {
        self.interim = Some(InterimSession {
            hash: surrogate_sha256,
            identity: identity.to_string(),
            credentials,
        });
        self
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
        let view = match &self.interim {
            Some(i) if i.hash == *surrogate_sha256 => SessionView {
                session: INTERIM_SESSION.to_string(),
                generation: 0,
                identity: i.identity.clone(),
                credentials: i.credentials.clone(),
            },
            _ => self.plane.lookup(surrogate_sha256)?,
        };
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
