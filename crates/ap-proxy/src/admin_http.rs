//! Admin socket: list live sessions and revoke all of them. It is served on its own Unix socket
//! in the proxy's private volume, which the agent container does not mount. The listing carries
//! identity, session and generation only, never a surrogate or a hash.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;

use crate::pipeline::App;
use crate::session_http::{error_reply, json_reply, with_registry};

/// Routes of the admin plane.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/admin/v1/sessions", get(list_sessions))
        .route("/admin/v1/revoke-all", post(revoke_all))
        .with_state(app)
}

async fn list_sessions(State(app): State<Arc<App>>) -> Response {
    let Some(rows) = with_registry(&app, |reg, now| reg.live_sessions(now)) else {
        return error_reply(503, "unavailable");
    };
    let sessions: Vec<_> = rows
        .iter()
        .map(|(identity, session, generation)| {
            json!({ "identity": identity, "session": session, "generation": generation })
        })
        .collect();
    json_reply(200, &json!({ "sessions": sessions }))
}

async fn revoke_all(State(app): State<Arc<App>>) -> Response {
    let Some(revoked) = with_registry(&app, |reg, _| reg.revoke_everything()) else {
        return error_reply(503, "unavailable");
    };
    let line = json!({ "event": "admin", "op": "revoke-all", "revoked": revoked, "status": 200 });
    app.audit.write_line(&line.to_string());
    json_reply(200, &json!({ "revoked": revoked }))
}
