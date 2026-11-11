//! Session-plane authority client (design Q1-B). One authority token per identity is held in
//! memory. Sessions are registered under it, renewed every 30 s, ended synchronously, and
//! resynced when the proxy reports a session it does not know.

use crate::surrogate::new_surrogate;
use crate::uds::{self, Reply, UdsError};
use ap_core::session_wire::{
    validate_entry, validate_session, Entry, HelloReq, HelloResp, RenewReq, RenewResp, ResyncReq,
    ResyncResp, SessionRef, WireErr,
};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;

/// Time between renew rounds while the proxy answers.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(30);

/// First retry delay after a failed renew round. Doubles on each failure.
const FIRST_RETRY: Duration = Duration::from_secs(1);

/// Longest wait between renew rounds while the proxy fails.
pub const MAX_RETRY: Duration = Duration::from_secs(10);

/// Failure of an authority call.
#[derive(Debug)]
pub enum AuthorityError {
    /// A field failed session-plane validation. No request was sent.
    Invalid(WireErr),
    /// The socket could not be reached, or the HTTP exchange failed.
    Transport(UdsError),
    /// The proxy answered with an unexpected status. `code` is its `error` field.
    Refused { status: u16, code: String },
    /// The proxy answered with a body that does not parse.
    Decode(serde_json::Error),
    /// An earlier end of the same session is still unconfirmed by the proxy. The registration
    /// was not sent. Retry after the next renew round has confirmed the revoke.
    RevokePending,
}

/// A surrogate for one registered session. The raw value goes to the child process only.
/// This type has no `Debug` or `Display`, so it is not printed by accident.
pub struct Surrogate(String);

impl Surrogate {
    /// The raw `aps_...` value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

struct Inner {
    socket: PathBuf,
    identity: String,
    token: Mutex<String>,
    live: Mutex<BTreeMap<(String, u64), Entry>>,
    /// Ended sessions whose DELETE the proxy has not confirmed. They are not renewed or resynced.
    /// Every renew round retries the DELETE until the proxy answers 2xx or 404.
    pending: Mutex<BTreeSet<(String, u64)>>,
}

impl Inner {
    fn token(&self) -> String {
        self.token.lock().expect("token lock").clone()
    }

    fn refs(&self) -> Vec<SessionRef> {
        self.live
            .lock()
            .expect("live lock")
            .values()
            .map(|e| SessionRef {
                session: e.session.clone(),
                generation: e.generation,
            })
            .collect()
    }

    fn entries(&self) -> Vec<Entry> {
        self.live
            .lock()
            .expect("live lock")
            .values()
            .cloned()
            .collect()
    }
}

/// Authority client for one identity. Dropping it stops the renew loop.
pub struct Authority {
    inner: Arc<Inner>,
    renewer: JoinHandle<()>,
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.renewer.abort();
    }
}

impl Authority {
    /// Take an authority token for `identity` from the proxy at `socket`, then start the renew
    /// loop. Must run inside a Tokio runtime.
    pub async fn start(
        identity: &str,
        socket: impl Into<PathBuf>,
    ) -> Result<Authority, AuthorityError> {
        let socket = socket.into();
        let token = hello(&socket, identity).await?;
        let inner = Arc::new(Inner {
            socket,
            identity: identity.to_string(),
            token: Mutex::new(token),
            live: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(BTreeSet::new()),
        });
        let renewer = tokio::spawn(renew_loop(Arc::clone(&inner)));
        Ok(Authority { inner, renewer })
    }

    /// Generate a surrogate, register the session under it, and return the surrogate. Only the
    /// digest leaves this process.
    pub async fn register(
        &self,
        session: &str,
        generation: u64,
        credentials: Vec<String>,
    ) -> Result<Surrogate, AuthorityError> {
        let (surrogate, surrogate_sha256) = new_surrogate();
        let entry = Entry {
            session: session.to_string(),
            generation,
            surrogate_sha256,
            credentials,
        };
        validate_entry(&entry).map_err(AuthorityError::Invalid)?;
        let key = (entry.session.clone(), generation);
        let pending = self
            .inner
            .pending
            .lock()
            .expect("pending lock")
            .contains(&key);
        if pending {
            // Send the old revoke first. Otherwise it would remove this new registration later.
            if !revoke_once(&self.inner, &key).await {
                return Err(AuthorityError::RevokePending);
            }
            self.inner
                .pending
                .lock()
                .expect("pending lock")
                .remove(&key);
        }
        let token = self.inner.token();
        let reply = uds::post_json(&self.inner.socket, "/v1/sessions", Some(&token), &entry)
            .await
            .map_err(AuthorityError::Transport)?;
        check(&reply, |s| (200..300).contains(&s))?;
        self.inner
            .live
            .lock()
            .expect("live lock")
            .insert((entry.session.clone(), generation), entry);
        Ok(Surrogate(surrogate))
    }

    /// End a session. The session stops being renewed at once. The call returns after the proxy
    /// confirms the DELETE. If the DELETE fails, the session stays pending and every later renew
    /// round retries it, so a restarted proxy never gets the session back from this client. A
    /// session the proxy does not know counts as ended.
    pub async fn end(&self, session: &str, generation: u64) -> Result<(), AuthorityError> {
        validate_session(session).map_err(AuthorityError::Invalid)?;
        let key = (session.to_string(), generation);
        self.inner.live.lock().expect("live lock").remove(&key);
        self.inner
            .pending
            .lock()
            .expect("pending lock")
            .insert(key.clone());
        let token = self.inner.token();
        let path = format!("/v1/sessions/{session}/{generation}");
        let reply = uds::delete(&self.inner.socket, &path, Some(&token))
            .await
            .map_err(AuthorityError::Transport)?;
        check(&reply, |s| (200..300).contains(&s) || s == 404)?;
        self.inner
            .pending
            .lock()
            .expect("pending lock")
            .remove(&key);
        Ok(())
    }

    /// One renew round: refresh the authority lease and every live session. If the proxy
    /// reports sessions it does not know, the full live list is resynced.
    pub async fn renew(&self) -> Result<(), AuthorityError> {
        renew_round(&self.inner).await
    }
}

async fn hello(socket: &Path, identity: &str) -> Result<String, AuthorityError> {
    let req = HelloReq {
        identity: identity.to_string(),
        nonce: None,
        proof: None,
    };
    let reply = uds::post_json(socket, "/v1/hello", None, &req)
        .await
        .map_err(AuthorityError::Transport)?;
    check(&reply, |s| (200..300).contains(&s))?;
    let resp: HelloResp = decode(&reply)?;
    Ok(resp.authority_token)
}

async fn renew_round(inner: &Inner) -> Result<(), AuthorityError> {
    flush_pending(inner).await;
    let token = inner.token();
    let req = RenewReq {
        sessions: inner.refs(),
    };
    let reply = uds::post_json(&inner.socket, "/v1/renew", Some(&token), &req)
        .await
        .map_err(AuthorityError::Transport)?;
    if reply.status == 401 {
        // The proxy no longer accepts this token. Take a new one, then restore every session.
        let fresh = hello(&inner.socket, &inner.identity).await?;
        *inner.token.lock().expect("token lock") = fresh;
        return resync(inner).await;
    }
    check(&reply, |s| (200..300).contains(&s))?;
    let resp: RenewResp = decode(&reply)?;
    if resp.unknown.is_empty() {
        Ok(())
    } else {
        resync_after_unknown(inner, &resp.unknown).await
    }
}

/// Resync after renew reported `unknown`. If the proxy rejects the batch with 409, it revoked
/// one of the listed surrogates (an admin revoke-all does this). The sessions renew reported as
/// unknown are dropped from the live set, and the rest are sent again.
async fn resync_after_unknown(inner: &Inner, unknown: &[SessionRef]) -> Result<(), AuthorityError> {
    match resync(inner).await {
        Err(AuthorityError::Refused { status: 409, .. }) => {
            {
                let mut live = inner.live.lock().expect("live lock");
                for r in unknown {
                    live.remove(&(r.session.clone(), r.generation));
                }
            }
            resync(inner).await
        }
        other => other,
    }
}

/// Retry every pending revoke. An entry leaves the set only when the proxy answers 2xx or 404.
/// A failed attempt stays pending for the next round.
async fn flush_pending(inner: &Inner) {
    let pending: Vec<(String, u64)> = inner
        .pending
        .lock()
        .expect("pending lock")
        .iter()
        .cloned()
        .collect();
    for key in pending {
        if revoke_once(inner, &key).await {
            inner.pending.lock().expect("pending lock").remove(&key);
        }
    }
}

/// Send one DELETE for an ended session. True when the proxy confirmed it (2xx or 404).
async fn revoke_once(inner: &Inner, key: &(String, u64)) -> bool {
    let token = inner.token();
    let path = format!("/v1/sessions/{}/{}", key.0, key.1);
    match uds::delete(&inner.socket, &path, Some(&token)).await {
        Ok(reply) => (200..300).contains(&reply.status) || reply.status == 404,
        Err(_) => false,
    }
}

async fn resync(inner: &Inner) -> Result<(), AuthorityError> {
    let token = inner.token();
    let req = ResyncReq {
        sessions: inner.entries(),
    };
    let reply = uds::put_json(&inner.socket, "/v1/sessions", Some(&token), &req)
        .await
        .map_err(AuthorityError::Transport)?;
    check(&reply, |s| (200..300).contains(&s))?;
    let resp: ResyncResp = decode(&reply)?;
    // The proxy skipped these keys because their absolute TTL has passed. Keep them out of the
    // live map, so renew and later resyncs do not send them again.
    let mut live = inner.live.lock().expect("live lock");
    for r in &resp.expired {
        live.remove(&(r.session.clone(), r.generation));
    }
    Ok(())
}

async fn renew_loop(inner: Arc<Inner>) {
    let mut wait = RENEW_INTERVAL;
    let mut retry = FIRST_RETRY;
    loop {
        tokio::time::sleep(wait).await;
        match renew_round(&inner).await {
            Ok(()) => {
                wait = RENEW_INTERVAL;
                retry = FIRST_RETRY;
            }
            Err(_) => {
                eprintln!("ap-client: renew failed, retrying in {retry:?}");
                wait = retry;
                retry = (retry * 2).min(MAX_RETRY);
            }
        }
    }
}

/// Accept the reply when `ok` says so, otherwise return its status and error code.
fn check(reply: &Reply, ok: impl Fn(u16) -> bool) -> Result<(), AuthorityError> {
    if ok(reply.status) {
        return Ok(());
    }
    let code = serde_json::from_slice::<serde_json::Value>(&reply.body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_default();
    Err(AuthorityError::Refused {
        status: reply.status,
        code,
    })
}

fn decode<T: DeserializeOwned>(reply: &Reply) -> Result<T, AuthorityError> {
    serde_json::from_slice(&reply.body).map_err(AuthorityError::Decode)
}
