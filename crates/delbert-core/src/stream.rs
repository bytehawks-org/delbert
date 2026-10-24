//! Live status for the console: a stream of "something changed" hints (Server-Sent Events).
//!
//! The stream carries no data, only the kind of change and nothing about its content: the console
//! refetches what it shows. Changes come from PostgreSQL `LISTEN/NOTIFY` (channel `delbert_changes`):
//! every audit event and every stored agent report notifies from inside the statement that wrote it,
//! so the hint is delivered **after commit** and also reaches Core replicas that did not do the write.
//! A client sees only the changes of tenants it can reach (`tenants:read`), platform changes
//! (no tenant) only with a global grant.

use std::{convert::Infallible, time::Duration};

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::Stream;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgListener, types::Uuid};
use tokio::sync::broadcast;

use crate::{
    api::AppState,
    auth::{Authn, CurrentUser},
};

/// Postgres channel the writers notify.
pub const CHANNEL: &str = "delbert_changes";

/// One hint. `kind` is `audit` (something was done), `report` (an agent reported) or `resync`
/// (the Core lost its listener for a moment: refetch everything).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub tenant: Option<Uuid>,
    pub kind: String,
}

/// A channel without a listener (tests that do not stream, Cores without a database listener).
pub fn channel() -> broadcast::Sender<Change> {
    broadcast::channel(256).0
}

/// Feed `tx` from PostgreSQL notifications; reconnects forever and tells subscribers to resync.
pub fn spawn_listener(pool: PgPool, tx: broadcast::Sender<Change>) {
    tokio::spawn(async move {
        loop {
            match listen(&pool, &tx).await {
                Ok(()) => return,
                Err(e) => tracing::warn!("change listener lost ({e}); retrying"),
            }
            let _ = tx.send(Change { tenant: None, kind: "resync".into() });
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

async fn listen(pool: &PgPool, tx: &broadcast::Sender<Change>) -> Result<(), sqlx::Error> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(CHANNEL).await?;
    loop {
        let note = listener.recv().await?;
        if let Some(change) = parse(note.payload()) {
            let _ = tx.send(change); // nobody listening is fine
        }
    }
}

/// `{"t": "<tenant uuid>" | null, "k": "<kind>"}`.
fn parse(payload: &str) -> Option<Change> {
    let v: Value = serde_json::from_str(payload).ok()?;
    Some(Change { tenant: v["t"].as_str().and_then(|t| t.parse().ok()), kind: v["k"].as_str()?.to_owned() })
}

/// Does `user` get to hear about `change`?
pub fn visible(user: &CurrentUser, change: &Change) -> bool {
    if change.kind == "resync" {
        return true; // carries nothing
    }
    match (user.tenants_with("tenants:read"), change.tenant) {
        (None, _) => true,
        (Some(allowed), Some(t)) => allowed.contains(&t),
        (Some(_), None) => false,
    }
}

/// Notify from SQL: used inside the statements that write.
pub fn notify_sql(kind: &str) -> String {
    format!("SELECT pg_notify('{CHANNEL}', json_build_object('t', $1::uuid, 'k', '{kind}')::text)")
}

#[utoipa::path(get, path = "/v1/stream", tag = "status", security(("bearer" = [])),
    responses((status = 200, description = "Server-Sent Events: `data: {\"kind\": \"audit\" | \"report\" | \"resync\"}` whenever something visible to the caller changed; a comment line every 15 s keeps the connection open", content_type = "text/event-stream")))]
pub async fn events(State(st): State<AppState>, Authn(user): Authn) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = st.changes.subscribe();
    let stream = futures::stream::unfold((rx, user), |(mut rx, user)| async move {
        loop {
            match rx.recv().await {
                Ok(change) if visible(&user, &change) => return Some((Ok(Event::default().data(json!({ "kind": change.kind }).to_string())), (rx, user))),
                Ok(_) => continue,
                // A slow client missed hints: one resync replaces them.
                Err(broadcast::error::RecvError::Lagged(_)) => return Some((Ok(Event::default().data(json!({ "kind": "resync" }).to_string())), (rx, user))),
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_are_parsed_and_junk_is_ignored() {
        let id = Uuid::nil();
        assert_eq!(parse(&format!(r#"{{"t":"{id}","k":"audit"}}"#)), Some(Change { tenant: Some(id), kind: "audit".into() }));
        assert_eq!(parse(r#"{"t":null,"k":"report"}"#), Some(Change { tenant: None, kind: "report".into() }));
        assert_eq!(parse("not json"), None);
        assert_eq!(parse(r#"{"t":null}"#), None);
    }
}
