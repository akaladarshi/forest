// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! This module contains the migration logic for the `NV19` upgrade for the
//! Miner actor.

use crate::state_migration::common::{
    ActorMigration, ActorMigrationInput, ActorMigrationOutput, TypeMigration, TypeMigrator,
};
use crate::utils::db::CborStoreExt as _;
use cid::Cid;
use fil_actor_miner_state::{v10::State as MinerStateOld, v11::State as MinerStateNew};
use fvm_ipld_blockstore::Blockstore;
use std::sync::Arc;

pub struct MinerMigrator(Cid);

pub(in crate::state_migration) fn miner_migrator<BS: Blockstore>(
    cid: Cid,
) -> Arc<dyn ActorMigration<BS> + Send + Sync> {
    Arc::new(MinerMigrator(cid))
}

impl<BS: Blockstore> ActorMigration<BS> for MinerMigrator {
    fn migrate_state(
        &self,
        store: &BS,
        input: ActorMigrationInput,
    ) -> anyhow::Result<Option<ActorMigrationOutput>> {
        let in_state: MinerStateOld = store.get_cbor_required(&input.head)?;
        let out_state: MinerStateNew = TypeMigrator::migrate_type(in_state, &store)?;
        let new_head = store.put_cbor_default(&out_state)?;
        Ok(Some(ActorMigrationOutput {
            new_code_cid: self.0,
            new_head,
        }))
    }
}
