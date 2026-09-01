use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    AgentError, AgentIdentity, Clock, CredentialRecord, CredentialStore, IdempotencyKeyProvider,
    IdentityStore, InspectCache, InspectCacheEntry, OperationKey,
};

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Default)]
pub struct TimerDelay;

#[async_trait]
impl crate::Delay for TimerDelay {
    async fn sleep(&self, duration: std::time::Duration) {
        futures_timer::Delay::new(duration).await;
    }
}

#[derive(Default)]
pub struct RandomIdempotencyKeyProvider;

#[async_trait]
impl IdempotencyKeyProvider for RandomIdempotencyKeyProvider {
    async fn create_key(&self, _operation: &OperationKey) -> Result<String, AgentError> {
        Ok(Uuid::new_v4().to_string())
    }
}

#[derive(Default)]
pub struct MemoryIdentityStore {
    entries: Mutex<BTreeMap<String, AgentIdentity>>,
}

#[async_trait]
impl IdentityStore for MemoryIdentityStore {
    async fn find(&self, service_did: &str) -> Result<Option<AgentIdentity>, AgentError> {
        Ok(self
            .entries
            .lock()
            .map_err(lock_error)?
            .get(service_did)
            .cloned())
    }
    async fn save(&self, identity: AgentIdentity) -> Result<(), AgentError> {
        self.entries
            .lock()
            .map_err(lock_error)?
            .insert(identity.service_did.clone(), identity);
        Ok(())
    }
}

pub struct MemoryCredentialStore {
    clock: Arc<dyn Clock>,
    entries: Mutex<BTreeMap<(String, String), CredentialRecord>>,
}

impl MemoryCredentialStore {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            entries: Mutex::new(BTreeMap::new()),
        }
    }
}

#[async_trait]
impl CredentialStore for MemoryCredentialStore {
    async fn delete(&self, service_did: &str, credential_id: &str) -> Result<(), AgentError> {
        self.entries
            .lock()
            .map_err(lock_error)?
            .remove(&(service_did.to_owned(), credential_id.to_owned()));
        Ok(())
    }
    async fn find(
        &self,
        service_did: &str,
        credential_id: &str,
    ) -> Result<Option<CredentialRecord>, AgentError> {
        let key = (service_did.to_owned(), credential_id.to_owned());
        let mut entries = self.entries.lock().map_err(lock_error)?;
        if entries
            .get(&key)
            .is_some_and(|record| record.expires_at <= self.clock.now())
        {
            entries.remove(&key);
        }
        Ok(entries.get(&key).cloned())
    }
    async fn list(&self, service_did: &str) -> Result<Vec<CredentialRecord>, AgentError> {
        let now = self.clock.now();
        let mut entries = self.entries.lock().map_err(lock_error)?;
        entries.retain(|_, record| record.expires_at > now);
        let mut records = entries
            .values()
            .filter(|record| record.service_did == service_did)
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            right
                .issued_at
                .cmp(&left.issued_at)
                .then_with(|| left.credential_id.cmp(&right.credential_id))
        });
        Ok(records)
    }
    async fn save(&self, credential: CredentialRecord) -> Result<(), AgentError> {
        crate::authentication::validate_record(
            &credential,
            &credential.service_did,
            self.clock.now(),
        )?;
        let key = (
            credential.service_did.clone(),
            credential.credential_id.clone(),
        );
        self.entries
            .lock()
            .map_err(lock_error)?
            .insert(key, credential);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryInspectCache {
    entries: Mutex<BTreeMap<String, InspectCacheEntry>>,
}

#[async_trait]
impl InspectCache for MemoryInspectCache {
    async fn delete(&self, inspect_url: &Url) -> Result<(), AgentError> {
        self.entries
            .lock()
            .map_err(lock_error)?
            .remove(inspect_url.as_str());
        Ok(())
    }
    async fn find(&self, inspect_url: &Url) -> Result<Option<InspectCacheEntry>, AgentError> {
        Ok(self
            .entries
            .lock()
            .map_err(lock_error)?
            .get(inspect_url.as_str())
            .cloned())
    }
    async fn save(&self, inspect_url: &Url, entry: InspectCacheEntry) -> Result<(), AgentError> {
        self.entries
            .lock()
            .map_err(lock_error)?
            .insert(inspect_url.to_string(), entry);
        Ok(())
    }
}

fn lock_error<T>(_error: std::sync::PoisonError<T>) -> AgentError {
    AgentError::Store("AEP Agent memory store lock is poisoned".to_owned())
}
