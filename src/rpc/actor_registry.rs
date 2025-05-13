// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT
use crate::lotus_json::HasLotusJson;
use crate::networks::ACTOR_BUNDLES_METADATA;
use crate::shim::actors::{AccountActorStateLoad, CronActorStateLoad, account, cron};
use crate::shim::machine::BuiltinActor;
use crate::shim::message::MethodNum;
use ahash::{HashMap, HashMapExt};
use anyhow::{Result, anyhow};
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;
use serde_json::Value;

// Build a map from CIDs to actor types and versions once at startup
static CID_TO_ACTOR_TYPE: Lazy<HashMap<Cid, (BuiltinActor, u64)>> = Lazy::new(|| {
    let mut map = HashMap::new();

    for ((_, _), metadata) in ACTOR_BUNDLES_METADATA.iter() {
        if let Ok(version) = metadata.actor_major_version() {
            for (actor_type, cid) in metadata.manifest.builtin_actors() {
                map.insert(cid, (actor_type, version));
            }
        }
    }

    map
});

// Global registry for method parameter deserialization
static METHOD_REGISTRY: Lazy<MethodRegistry> = Lazy::new(|| {
    let mut registry = MethodRegistry::new();
    register_known_methods(&mut registry);
    registry
});

type ParamDeserializerFn = Box<dyn Fn(&[u8]) -> Result<Value> + Send + Sync>;

pub struct MethodRegistry {
    // (code_cid, method_num) -> method param deserializer
    deserializers: HashMap<(Cid, MethodNum), ParamDeserializerFn>,
}

impl MethodRegistry {
    fn new() -> Self {
        Self {
            deserializers: HashMap::new(),
        }
    }

    fn register_method<P: 'static + DeserializeOwned + HasLotusJson>(
        &mut self,
        code_cid: Cid,
        method_num: MethodNum,
        deserializer: fn(&[u8]) -> Result<P>,
    ) {
        let boxed_deserializer: ParamDeserializerFn = Box::new(move |bytes| -> Result<Value> {
            let param: P = deserializer(bytes)?;
            serde_json::to_value(param.into_lotus_json())
                .map_err(|e| anyhow!("Failed to serialize method param into JSON: {}", e))
        });

        self.deserializers
            .insert((code_cid, method_num), boxed_deserializer);
    }

    fn deserialize_params(
        &self,
        code_cid: &Cid,
        method_num: MethodNum,
        params_bytes: &[u8],
    ) -> Result<Option<Value>> {
        if let Some(deserializer) = self.deserializers.get(&(*code_cid, method_num)) {
            return Ok(Some(deserializer(params_bytes)?));
        }

        let (actor_type, version) = get_actor_type_from_code(code_cid)?;

        Err(anyhow!(
            "No deserializer registered for actor type {:?} (v{}), method {}",
            actor_type,
            version,
            method_num
        ))
    }
}

pub fn get_actor_type_from_code(code_cid: &Cid) -> Result<(BuiltinActor, u64)> {
    CID_TO_ACTOR_TYPE
        .get(code_cid)
        .copied()
        .ok_or_else(|| anyhow!("Unknown actor code CID: {}", code_cid))
}

pub fn load_and_serialize_actor_state<BS>(
    store: &BS,
    code_cid: &Cid,
    state_cid: &Cid,
) -> Result<Value>
where
    BS: Blockstore,
{
    let (actor_type, _) = get_actor_type_from_code(code_cid)?;

    match actor_type {
        BuiltinActor::Account => {
            let state = account::State::load(store, *code_cid, *state_cid)
                .map_err(|e| anyhow!("Failed to load account actor state: {}", e))?;
            Ok(serde_json::to_value(state.into_lotus_json())
                .map_err(|e| anyhow!("Failed to serialize account state to JSON: {}", e))?)
        }
        BuiltinActor::Cron => {
            let state = cron::State::load(store, *code_cid, *state_cid)
                .map_err(|e| anyhow!("Failed to load cron actor state: {}", e))?;
            Ok(serde_json::to_value(state.into_lotus_json())
                .map_err(|e| anyhow!("Failed to serialize cron state to JSON: {}", e))?)
        }
        _ => Err(anyhow!(
            "No serializer implemented for actor type: {:?}",
            actor_type
        )),
    }
}

pub fn deserialize_params(
    code_cid: &Cid,
    method_num: MethodNum,
    params_bytes: &[u8],
) -> Result<Option<Value>> {
    METHOD_REGISTRY.deserialize_params(code_cid, method_num, params_bytes)
}

fn register_known_methods(registry: &mut MethodRegistry) {
    for (&cid, &(actor_type, version)) in CID_TO_ACTOR_TYPE.iter() {
        match (actor_type, version) {
            (BuiltinActor::Miner, 15) => {
                register_miner_v15_methods(registry, cid);
            }
            (BuiltinActor::Miner, 16) => {
                register_miner_v16_methods(registry, cid);
            }
            (BuiltinActor::Account, 16) => {
                register_account_v16_methods(registry, cid);
            }
            (BuiltinActor::Account, 15) => {
                register_account_v15_methods(registry, cid);
            }
            (BuiltinActor::EVM, 16) => {
                register_evm_v16_methods(registry, cid);
            }
            (BuiltinActor::EVM, 15) => {
                register_evm_v15_methods(registry, cid);
            }
            _ => {}
        }
    }
}

macro_rules! register_actor_methods {
    ($registry:expr, $code_cid:expr, $version:expr, [
        $( ($method:expr, $param_type:ty) ),* $(,)?
    ]) => {
        $(
            $registry.register_method(
                $code_cid,
                $method as MethodNum,
                |bytes| -> Result<$param_type> { Ok(fvm_ipld_encoding::from_slice(bytes)?) },
            );
        )*
    };
}

fn register_account_v15_methods(registry: &mut MethodRegistry, code_cid: Cid) {
    use fil_actor_account_state::v15::{Method, types};

    register_actor_methods!(
        registry,
        code_cid,
        15,
        [
            (Method::Constructor, types::ConstructorParams),
            (
                Method::AuthenticateMessageExported,
                types::AuthenticateMessageParams
            )
        ]
    );
}

fn register_account_v16_methods(registry: &mut MethodRegistry, code_cid: Cid) {
    use fil_actor_account_state::v16::{Method, types};

    register_actor_methods!(
        registry,
        code_cid,
        16,
        [
            (Method::Constructor, types::ConstructorParams),
            (
                Method::AuthenticateMessageExported,
                types::AuthenticateMessageParams
            )
        ]
    );
}

fn register_miner_v15_methods(registry: &mut MethodRegistry, code_cid: Cid) {
    use fil_actor_miner_state::v15::Method;

    register_actor_methods!(
        registry,
        code_cid,
        15,
        [
            (
                Method::Constructor,
                fil_actor_miner_state::v15::MinerConstructorParams
            ),
            (
                Method::ChangeWorkerAddress,
                fil_actor_miner_state::v15::ChangeWorkerAddressParams
            ),
        ]
    );
}

fn register_miner_v16_methods(registry: &mut MethodRegistry, code_cid: Cid) {
    use fil_actor_miner_state::v16::Method;

    register_actor_methods!(
        registry,
        code_cid,
        16,
        [
            (
                Method::Constructor,
                fil_actor_miner_state::v16::MinerConstructorParams
            ),
            (
                Method::ChangeWorkerAddress,
                fil_actor_miner_state::v16::ChangeWorkerAddressParams
            ),
        ]
    );
}

fn register_evm_v15_methods(registry: &mut MethodRegistry, code_cid: Cid) {
    use fil_actor_evm_state::v15::Method;

    register_actor_methods!(
        registry,
        code_cid,
        15,
        [(
            Method::Constructor,
            fil_actor_evm_state::v15::ConstructorParams
        )]
    );
}

fn register_evm_v16_methods(registry: &mut MethodRegistry, code_cid: Cid) {
    use fil_actor_evm_state::v16::Method;

    register_actor_methods!(
        registry,
        code_cid,
        16,
        [(
            Method::Constructor,
            fil_actor_evm_state::v16::ConstructorParams
        )]
    );
}
