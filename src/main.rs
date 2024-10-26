#![no_main]
use futures::executor;

use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

use async_trait::async_trait;
use blind_rsa_signatures::{KeyPair, PublicKey};
use privacypass::{public_tokens::server::*, Nonce, NonceStore, TruncatedTokenKeyId};

use rand::{CryptoRng, RngCore};

entrypoint::entrypoint!(main);

#[derive(Default)]
pub struct MemoryNonceStore {
    nonces: Mutex<HashSet<Nonce>>,
}

#[async_trait]
impl NonceStore for MemoryNonceStore {
    async fn exists(&self, nonce: &Nonce) -> bool {
        let nonces = self.nonces.lock().await;
        nonces.contains(nonce)
    }

    async fn insert(&self, nonce: Nonce) {
        let mut nonces = self.nonces.lock().await;
        nonces.insert(nonce);
    }
}

#[derive(Default)]
pub struct IssuerMemoryKeyStore {
    keys: Mutex<HashMap<TruncatedTokenKeyId, KeyPair>>,
}

#[async_trait]
impl IssuerKeyStore for IssuerMemoryKeyStore {
    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, key_pair: KeyPair) {
        let mut keys = self.keys.lock().await;
        keys.insert(truncated_token_key_id, key_pair);
    }

    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<KeyPair> {
        self.keys.lock().await.get(truncated_token_key_id).cloned()
    }
}

#[derive(Default)]
pub struct OriginMemoryKeyStore {
    keys: Mutex<HashMap<TruncatedTokenKeyId, PublicKey>>,
}

#[async_trait]
impl OriginKeyStore for OriginMemoryKeyStore {
    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, public_key: PublicKey) {
        let mut keys = self.keys.lock().await;
        keys.insert(truncated_token_key_id, public_key);
    }

    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<PublicKey> {
        self.keys.lock().await.get(truncated_token_key_id).cloned()
    }
}

async fn create_public_keypair<R: RngCore + CryptoRng>(
    rng: &mut R,
    key_store: IssuerMemoryKeyStore,
    server: &privacypass::public_tokens::server::IssuerServer,
) {
    let _public_key = server.create_keypair(rng, &key_store).await.unwrap();
}

fn main() {
    entrypoint::io::println(&format!("zkpp init"));

    let mut rng = rand::thread_rng();
    let key_store = IssuerMemoryKeyStore::default();
    let server = privacypass::public_tokens::server::IssuerServer::new();
    let _ = executor::block_on(async {
        entrypoint::io::println(&format!("creating keypair"));
        create_public_keypair(&mut rng, key_store, &server).await;
    });
    entrypoint::io::println(&format!("IssuerServer: {:?}", server));
}
