use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::{
    ClientAssertionReplayRecord, ClientAssertionReplayStore, Clock, CommandIdempotencyInput,
    CommandIdempotencyRecord, CommandIdempotencyResult, CommandIdempotencyStore, CommandOperation,
    EnrollmentDecision, EnrollmentPolicy, EnrollmentRecord, EnrollmentStore, ServiceError,
};

type IdempotencyKey = (String, String);
type IdempotencyLock = Arc<futures::lock::Mutex<()>>;

/// How long a replayable command result stays available.
///
/// CORE-IDP-004 requires at least one hour, so a record is still replayable at exactly that age
/// and is dropped after it, which is what keeps the store from growing without bound.
const IDEMPOTENCY_RETENTION: Duration = Duration::from_secs(3600);

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

pub struct StaticEnrollmentPolicy {
    decision: EnrollmentDecision,
}

impl StaticEnrollmentPolicy {
    pub fn new(decision: EnrollmentDecision) -> Self {
        Self { decision }
    }
}

impl Default for StaticEnrollmentPolicy {
    fn default() -> Self {
        Self::new(EnrollmentDecision::default())
    }
}

#[async_trait]
impl EnrollmentPolicy for StaticEnrollmentPolicy {
    async fn decide(
        &self,
        _request: &aep_core::EnrollRequest,
        _now: OffsetDateTime,
    ) -> Result<EnrollmentDecision, ServiceError> {
        Ok(self.decision.clone())
    }
}

#[derive(Default)]
pub struct MemoryEnrollmentStore {
    records: Mutex<BTreeMap<String, EnrollmentRecord>>,
}

impl MemoryEnrollmentStore {
    pub fn new(records: impl IntoIterator<Item = EnrollmentRecord>) -> Result<Self, ServiceError> {
        let mut entries = BTreeMap::new();
        for record in records {
            if record.agent_did.is_empty() {
                return Err(ServiceError::Store(
                    "AEP enrollment Agent DID must not be empty".to_owned(),
                ));
            }
            entries.insert(record.agent_did.clone(), record);
        }
        Ok(Self {
            records: Mutex::new(entries),
        })
    }
}

#[async_trait]
impl EnrollmentStore for MemoryEnrollmentStore {
    async fn find(&self, agent_did: &str) -> Result<Option<EnrollmentRecord>, ServiceError> {
        Ok(self
            .records
            .lock()
            .map_err(lock_error)?
            .get(agent_did)
            .cloned())
    }

    async fn save(&self, record: EnrollmentRecord) -> Result<EnrollmentRecord, ServiceError> {
        if record.agent_did.is_empty() {
            return Err(ServiceError::Store(
                "AEP enrollment Agent DID must not be empty".to_owned(),
            ));
        }
        self.records
            .lock()
            .map_err(lock_error)?
            .insert(record.agent_did.clone(), record.clone());
        Ok(record)
    }
}

#[derive(Default)]
pub struct MemoryClientAssertionReplayStore {
    records: Mutex<BTreeMap<(String, String), ClientAssertionReplayRecord>>,
}

#[async_trait]
impl ClientAssertionReplayStore for MemoryClientAssertionReplayStore {
    async fn consume(
        &self,
        record: ClientAssertionReplayRecord,
        now: OffsetDateTime,
    ) -> Result<bool, ServiceError> {
        let mut records = self.records.lock().map_err(lock_error)?;
        records.retain(|_, existing| existing.expires_at > now);
        let key = (record.sub.clone(), record.jti.clone());
        if records.contains_key(&key) {
            return Ok(false);
        }
        records.insert(key, record);
        Ok(true)
    }
}

pub struct MemoryCommandIdempotencyStore {
    clock: Arc<dyn Clock>,
    locks: Mutex<BTreeMap<IdempotencyKey, IdempotencyLock>>,
    records: Mutex<BTreeMap<IdempotencyKey, CommandIdempotencyRecord>>,
}

impl Default for MemoryCommandIdempotencyStore {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl MemoryCommandIdempotencyStore {
    /// Builds an empty store that reads the time from `clock`, which is what decides when a
    /// stored result has outlived its retention.
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            locks: Mutex::new(BTreeMap::new()),
            records: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn new(
        records: impl IntoIterator<Item = CommandIdempotencyRecord>,
    ) -> Result<Self, ServiceError> {
        let mut entries = BTreeMap::new();
        for record in records {
            let key = (
                record.input.agent_did.clone(),
                record.input.idempotency_key.clone(),
            );
            if key.0.is_empty() || key.1.is_empty() {
                return Err(ServiceError::Store(
                    "AEP idempotency record key must not be empty".to_owned(),
                ));
            }
            entries.insert(key, record);
        }
        Ok(Self {
            clock: Arc::new(SystemClock),
            locks: Mutex::new(BTreeMap::new()),
            records: Mutex::new(entries),
        })
    }

    fn command_lock(&self, key: &IdempotencyKey) -> Result<IdempotencyLock, ServiceError> {
        Ok(self
            .locks
            .lock()
            .map_err(lock_error)?
            .entry(key.clone())
            .or_default()
            .clone())
    }

    fn release_command_lock(
        &self,
        key: &IdempotencyKey,
        command_lock: &IdempotencyLock,
    ) -> Result<(), ServiceError> {
        let mut locks = self.locks.lock().map_err(lock_error)?;
        if locks
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, command_lock))
            && Arc::strong_count(command_lock) == 2
        {
            locks.remove(key);
        }
        Ok(())
    }
}

#[async_trait]
impl CommandIdempotencyStore for MemoryCommandIdempotencyStore {
    async fn execute(
        &self,
        input: CommandIdempotencyInput,
        operation: CommandOperation,
    ) -> Result<CommandIdempotencyResult, ServiceError> {
        let key = (input.agent_did.clone(), input.idempotency_key.clone());
        let command_lock = self.command_lock(&key)?;
        let result = {
            let _guard = command_lock.lock().await;
            let now = self.clock.now();
            let existing = {
                let mut records = self.records.lock().map_err(lock_error)?;
                records.retain(|_, record| record.created_at + IDEMPOTENCY_RETENTION >= now);
                records.get(&key).cloned()
            };
            if let Some(record) = existing {
                if record.input.command == input.command
                    && record.input.request_hash == input.request_hash
                {
                    Ok(CommandIdempotencyResult::Replayed(record.response))
                } else {
                    Ok(CommandIdempotencyResult::Conflict)
                }
            } else {
                match operation().await {
                    Ok(response) => {
                        let created_at = self.clock.now();
                        self.records.lock().map_err(lock_error)?.insert(
                            key.clone(),
                            CommandIdempotencyRecord {
                                input,
                                response: response.clone(),
                                created_at,
                            },
                        );
                        Ok(CommandIdempotencyResult::Created(response))
                    }
                    Err(error) => Err(error),
                }
            }
        };
        self.release_command_lock(&key, &command_lock)?;
        result
    }
}

fn lock_error<T>(_error: std::sync::PoisonError<T>) -> ServiceError {
    ServiceError::Store("AEP Service memory store lock is poisoned".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_an_idempotency_lock_while_another_request_holds_it() {
        let store = MemoryCommandIdempotencyStore::default();
        let key = ("did:web:agent.example".to_owned(), "request-1".to_owned());
        let first = store.command_lock(&key).expect("first lock");
        let waiting = store.command_lock(&key).expect("waiting lock");

        store
            .release_command_lock(&key, &first)
            .expect("retain lock");
        let concurrent = store.command_lock(&key).expect("concurrent lock");
        assert!(Arc::ptr_eq(&first, &waiting));
        assert!(Arc::ptr_eq(&first, &concurrent));

        drop(waiting);
        drop(concurrent);
        store
            .release_command_lock(&key, &first)
            .expect("release lock");
        assert!(!store.locks.lock().expect("locks").contains_key(&key));
    }
}
