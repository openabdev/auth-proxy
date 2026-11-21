//! The owner's Telegram button presses (stage 2 buttons).
//!
//! An update reaches [`decide`] only after the poller checked that it came from the owner id and
//! has the fixed callback shape. `decide` then runs the same decision the approval page runs:
//! the nonce must match the live hold, the policy is read under the table lock for an approve,
//! and the approve waits for the handler's confirmation exactly as the page's approve does. The
//! hold handler writes the audit lines, so this module writes none.

use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::PolicySource;
use crate::hold::{CallbackRefusal, CallbackTransition, Confirm, HeldRequest, Table};
use crate::notify::poll::{run, Callback, TelegramPoller, Update};

/// The approver label the audit records for a Telegram decision. The owner's numeric id is never
/// written.
pub const APPROVER: &str = "telegram-owner";

/// What one press decided.
pub(crate) struct Outcome {
    /// The short reply the presser sees.
    pub reply: &'static str,
    /// For an approve that won: the handler's confirmation, to wait on after the reply is sent.
    pub confirm: Option<oneshot::Receiver<Confirm>>,
}

/// Apply one owner press to `table`. `still_held` is the policy check, read under the table lock.
pub(crate) fn decide(
    table: &Table,
    still_held: impl FnOnce(&str, &HeldRequest) -> bool,
    cb: &Callback,
) -> Outcome {
    match table.transition_by_callback(&cb.request_id, &cb.nonce, cb.action, APPROVER, still_held) {
        CallbackTransition::ApproveStarted(rx) => Outcome {
            reply: "Approved",
            confirm: Some(rx),
        },
        CallbackTransition::Denied => Outcome {
            reply: "Denied",
            confirm: None,
        },
        CallbackTransition::Refused(CallbackRefusal::PolicyChanged) => Outcome {
            reply: "No longer allowed",
            confirm: None,
        },
        // One text for a missing entry and a wrong nonce, so a reply never shows which check
        // failed.
        CallbackTransition::Refused(_) => Outcome {
            reply: "No longer waiting",
            confirm: None,
        },
    }
}

async fn serve(table: Arc<Table>, policy: PolicySource, poller: Arc<TelegramPoller>, u: Update) {
    match u {
        Update::Refused { callback_id, reply } => poller.answer(&callback_id, reply).await,
        Update::Callback(cb) => {
            let check = |identity: &str, req: &HeldRequest| {
                policy().is_some_and(|s| crate::passthrough::still_held(&s, identity, req))
            };
            let out = decide(&table, check, &cb);
            poller.answer(&cb.callback_id, out.reply).await;
            if let Some(rx) = out.confirm {
                // The result is already in the audit line the handler wrote.
                let _ = Table::await_confirm(rx).await;
            }
        }
    }
}

/// Long-poll for owner presses and serve each on its own task, so a slow approve never delays
/// the next press. The returned handle is aborted at shutdown.
pub(crate) fn spawn(
    table: Arc<Table>,
    policy: PolicySource,
    poller: TelegramPoller,
) -> JoinHandle<()> {
    let poller = Arc::new(poller);
    let p = Arc::clone(&poller);
    tokio::spawn(async move {
        run(p, move |u| {
            tokio::spawn(serve(
                Arc::clone(&table),
                Arc::clone(&policy),
                Arc::clone(&poller),
                u,
            ));
        })
        .await;
    })
}
