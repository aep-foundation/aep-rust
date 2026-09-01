use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
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

#[derive(Default)]
pub struct MemoryCommandIdempotencyStore {
    locks: Mutex<BTreeMap<IdempotencyKey, IdempotencyLock>>,
    records: Mutex<BTreeMap<IdempotencyKey, CommandIdempotencyRecord>>,
}

impl MemoryCommandIdempotencyStore {
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
            let existing = self.records.lock().map_err(lock_error)?.get(&key).cloned();
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
                        self.records.lock().map_err(lock_error)?.insert(
                            key.clone(),
                            CommandIdempotencyRecord {
                                input,
                                response: response.clone(),
                                created_at: OffsetDateTime::now_utc(),
                            },
                        );
                        Ok(CommandIdempotencyResult::Created(response))
                    }
                    Err(error) => Err(error),
                }
            }
        };
        self.locks.lock().map_err(lock_error)?.remove(&key);
        result
    }
}

fn lock_error<T>(_error: std::sync::PoisonError<T>) -> ServiceError {
    ServiceError::Store("AEP Service memory store lock is poisoned".to_owned())
}
