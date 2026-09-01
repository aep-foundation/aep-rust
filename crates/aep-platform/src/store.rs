use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::{
    Clock, IdempotencyInput, IdempotencyOperation, IdempotencyResult, IdempotencyStore,
    IdentityCreation, IdentityListQuery, IdentityListResult, IdentityRecord, IdentityStore,
    LifecyclePolicy, ManagedAgentStatus, PlatformError, ReplayStore, RequestContext,
    StoredResponse, validate_identity_record,
};

type ScopeLock = Arc<futures::lock::Mutex<()>>;
type IdempotencyKey = (String, String);

#[derive(Default)]
struct IdentityRecords {
    by_agent_did: BTreeMap<String, String>,
    by_agent_did_id: BTreeMap<String, String>,
    by_scope: BTreeMap<(String, String), String>,
    records: BTreeMap<String, IdentityRecord>,
}

#[derive(Default)]
pub struct MemoryIdentityStore {
    locks: Mutex<BTreeMap<(String, String), ScopeLock>>,
    records: Mutex<IdentityRecords>,
}

impl MemoryIdentityStore {
    fn scope_lock(&self, key: &(String, String)) -> Result<ScopeLock, PlatformError> {
        Ok(self
            .locks
            .lock()
            .map_err(lock_error)?
            .entry(key.clone())
            .or_default()
            .clone())
    }

    fn find_indexed(
        &self,
        key: &str,
        index: impl FnOnce(&IdentityRecords) -> &BTreeMap<String, String>,
    ) -> Result<Option<IdentityRecord>, PlatformError> {
        let records = self.records.lock().map_err(lock_error)?;
        Ok(index(&records)
            .get(key)
            .and_then(|identity_id| records.records.get(identity_id))
            .cloned())
    }

    fn release_scope_lock(
        &self,
        key: &(String, String),
        scope_lock: &ScopeLock,
    ) -> Result<(), PlatformError> {
        let mut locks = self.locks.lock().map_err(lock_error)?;
        if locks
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, scope_lock))
            && Arc::strong_count(scope_lock) == 2
        {
            locks.remove(key);
        }
        Ok(())
    }
}

#[async_trait]
impl IdentityStore for MemoryIdentityStore {
    async fn find_or_create(
        &self,
        principal: &str,
        service_did: &str,
        create: IdentityCreation,
    ) -> Result<IdentityRecord, PlatformError> {
        if principal.is_empty() || service_did.is_empty() {
            return Err(PlatformError::Store(
                "AEP Platform identity scope must not be empty".to_owned(),
            ));
        }
        let key = (principal.to_owned(), service_did.to_owned());
        let scope_lock = self.scope_lock(&key)?;
        let result = async {
            let _guard = scope_lock.lock().await;
            let existing = {
                let records = self.records.lock().map_err(lock_error)?;
                records
                    .by_scope
                    .get(&key)
                    .and_then(|identity_id| records.records.get(identity_id))
                    .cloned()
            };
            if let Some(existing) = existing {
                Ok(existing)
            } else {
                let identity = create().await?;
                validate_identity_record(&identity)?;
                if identity.principal != principal || identity.service_did != service_did {
                    return Err(PlatformError::Store(
                        "AEP Platform identity does not match its requested scope".to_owned(),
                    ));
                }
                let mut records = self.records.lock().map_err(lock_error)?;
                if records.records.contains_key(&identity.agent_identity_id)
                    || records.by_agent_did.contains_key(&identity.agent_did)
                    || records.by_agent_did_id.contains_key(&identity.agent_did_id)
                {
                    return Err(PlatformError::Store(
                        "AEP Platform identity material must be unique".to_owned(),
                    ));
                }
                records
                    .by_scope
                    .insert(key.clone(), identity.agent_identity_id.clone());
                records.by_agent_did.insert(
                    identity.agent_did.clone(),
                    identity.agent_identity_id.clone(),
                );
                records.by_agent_did_id.insert(
                    identity.agent_did_id.clone(),
                    identity.agent_identity_id.clone(),
                );
                records
                    .records
                    .insert(identity.agent_identity_id.clone(), identity.clone());
                Ok(identity)
            }
        }
        .await;
        self.release_scope_lock(&key, &scope_lock)?;
        result
    }

    async fn find_by_agent_did(
        &self,
        agent_did: &str,
    ) -> Result<Option<IdentityRecord>, PlatformError> {
        self.find_indexed(agent_did, |records| &records.by_agent_did)
    }

    async fn find_by_agent_did_id(
        &self,
        agent_did_id: &str,
    ) -> Result<Option<IdentityRecord>, PlatformError> {
        self.find_indexed(agent_did_id, |records| &records.by_agent_did_id)
    }

    async fn get(&self, agent_identity_id: &str) -> Result<Option<IdentityRecord>, PlatformError> {
        Ok(self
            .records
            .lock()
            .map_err(lock_error)?
            .records
            .get(agent_identity_id)
            .cloned())
    }

    async fn list(
        &self,
        principal: &str,
        query: &IdentityListQuery,
    ) -> Result<IdentityListResult, PlatformError> {
        if principal.is_empty() {
            return Err(PlatformError::Store(
                "AEP Platform identity-list principal must not be empty".to_owned(),
            ));
        }
        let mut identities = self
            .records
            .lock()
            .map_err(lock_error)?
            .records
            .values()
            .filter(|identity| {
                identity.principal == principal
                    && query
                        .service_did
                        .as_ref()
                        .is_none_or(|service_did| &identity.service_did == service_did)
                    && query.status.is_none_or(|status| identity.status == status)
            })
            .cloned()
            .collect::<Vec<_>>();
        identities.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.agent_identity_id.cmp(&right.agent_identity_id))
        });
        if query.descending {
            identities.reverse();
        }
        let total = identities.len();
        let identities = identities
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect();
        Ok(IdentityListResult { identities, total })
    }

    async fn update_status(
        &self,
        agent_identity_id: &str,
        status: ManagedAgentStatus,
        updated_at: OffsetDateTime,
    ) -> Result<Option<IdentityRecord>, PlatformError> {
        let mut records = self.records.lock().map_err(lock_error)?;
        let Some(identity) = records.records.get_mut(agent_identity_id) else {
            return Ok(None);
        };
        identity.status = status;
        identity.updated_at = updated_at;
        Ok(Some(identity.clone()))
    }
}

#[derive(Clone, Debug)]
struct IdempotencyRecord {
    input: IdempotencyInput,
    response: StoredResponse,
}

pub struct MemoryIdempotencyStore {
    clock: Arc<dyn Clock>,
    locks: Mutex<BTreeMap<IdempotencyKey, ScopeLock>>,
    records: Mutex<BTreeMap<IdempotencyKey, IdempotencyRecord>>,
}

impl MemoryIdempotencyStore {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            locks: Mutex::new(BTreeMap::new()),
            records: Mutex::new(BTreeMap::new()),
        }
    }

    fn operation_lock(&self, key: &IdempotencyKey) -> Result<ScopeLock, PlatformError> {
        Ok(self
            .locks
            .lock()
            .map_err(lock_error)?
            .entry(key.clone())
            .or_default()
            .clone())
    }

    fn release_operation_lock(
        &self,
        key: &IdempotencyKey,
        operation_lock: &ScopeLock,
    ) -> Result<(), PlatformError> {
        let mut locks = self.locks.lock().map_err(lock_error)?;
        if locks
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, operation_lock))
            && Arc::strong_count(operation_lock) == 2
        {
            locks.remove(key);
        }
        Ok(())
    }
}

#[async_trait]
impl IdempotencyStore for MemoryIdempotencyStore {
    async fn execute(
        &self,
        input: IdempotencyInput,
        operation: IdempotencyOperation,
    ) -> Result<IdempotencyResult, PlatformError> {
        if input.principal.is_empty()
            || input.idempotency_key.is_empty()
            || input.request_hash.is_empty()
        {
            return Err(PlatformError::Store(
                "AEP Platform idempotency input is invalid".to_owned(),
            ));
        }
        let key = (input.principal.clone(), input.idempotency_key.clone());
        let operation_lock = self.operation_lock(&key)?;
        let result = async {
            let _guard = operation_lock.lock().await;
            let now = self.clock.now();
            let existing = {
                let mut records = self.records.lock().map_err(lock_error)?;
                records.retain(|_, record| {
                    record.response.created_at + Duration::from_secs(3600) > now
                });
                records.get(&key).cloned()
            };
            if let Some(existing) = existing {
                if existing.input.operation == input.operation
                    && existing.input.request_hash == input.request_hash
                {
                    Ok(IdempotencyResult::Replayed(existing.response))
                } else {
                    Ok(IdempotencyResult::Conflict)
                }
            } else {
                let mut response = operation().await?;
                if response.created_at == OffsetDateTime::UNIX_EPOCH {
                    response.created_at = now;
                }
                self.records.lock().map_err(lock_error)?.insert(
                    key.clone(),
                    IdempotencyRecord {
                        input,
                        response: response.clone(),
                    },
                );
                Ok(IdempotencyResult::Created(response))
            }
        }
        .await;
        self.release_operation_lock(&key, &operation_lock)?;
        result
    }
}

impl Default for MemoryIdempotencyStore {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}

#[derive(Default)]
pub struct MemoryReplayStore {
    records: Mutex<BTreeMap<String, OffsetDateTime>>,
}

#[async_trait]
impl ReplayStore for MemoryReplayStore {
    async fn consume(
        &self,
        key: &str,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, PlatformError> {
        if key.is_empty() || expires_at <= now {
            return Ok(false);
        }
        let mut records = self.records.lock().map_err(lock_error)?;
        records.retain(|_, expiry| *expiry > now);
        if records.contains_key(key) {
            return Ok(false);
        }
        records.insert(key.to_owned(), expires_at);
        Ok(true)
    }
}

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Default)]
pub struct DefaultLifecyclePolicy;

#[async_trait]
impl LifecyclePolicy for DefaultLifecyclePolicy {
    async fn can_sign(
        &self,
        identity: &IdentityRecord,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(identity.status == ManagedAgentStatus::Active)
    }

    async fn can_transition(
        &self,
        _identity: &IdentityRecord,
        _status: ManagedAgentStatus,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(true)
    }

    async fn can_verify(
        &self,
        identity: &IdentityRecord,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(identity.status == ManagedAgentStatus::Active)
    }
}

fn lock_error<T>(_error: std::sync::PoisonError<T>) -> PlatformError {
    PlatformError::Store("AEP Platform memory store lock is poisoned".to_owned())
}
