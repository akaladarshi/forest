// Copyright 2019-2023 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use std::{
    fs::File as SyncFile,
    io::{self, copy as sync_copy, BufReader as SyncBufReader, ErrorKind},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use crate::{shim::sector::SectorSize, utils::net::download_ipfs_file_trustlessly};
use ahash::HashMap;
use backoff::{future::retry, ExponentialBackoffBuilder};
use blake2b_simd::{Hash, State as Blake2b};
use cid::Cid;
use serde::{Deserialize, Serialize};
use tokio::fs::{self};
use tracing::{debug, error, info, warn};

const GATEWAY: &str = "https://proofs.filecoin.io/ipfs/";
const PARAM_DIR: &str = "filecoin-proof-parameters";
const DIR_ENV: &str = "FIL_PROOFS_PARAMETER_CACHE";
const GATEWAY_ENV: &str = "IPFS_GATEWAY";
const TRUST_PARAMS_ENV: &str = "TRUST_PARAMS";
const DEFAULT_PARAMETERS: &str = include_str!("./parameters.json");

/// Sector size options for fetching.
pub enum SectorSizeOpt {
    /// All keys and proofs gen parameters
    All,
    /// Only verification parameters
    Keys,
    /// All keys and proofs gen parameters for a given size
    Size(SectorSize),
}

type ParameterMap = HashMap<String, ParameterData>;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ParameterData {
    cid: String,
    digest: String,
    sector_size: u64,
}

// Proof parameter file directory. Defaults to
// %DATA_DIR/filecoin-proof-parameters unless the FIL_PROOFS_PARAMETER_CACHE
// environment variable is set.
fn param_dir(data_dir: &Path) -> PathBuf {
    std::env::var(PathBuf::from(DIR_ENV))
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join(PARAM_DIR))
}

/// Forest uses a set of external crates for verifying the proofs generated by
/// the miners. These external crates require a specific set of parameter files
/// to be located at in a specific folder. By default, it is
/// `/var/tmp/filecoin-proof-parameters` but it can be overridden by the
/// `FIL_PROOFS_PARAMETER_CACHE` environment variable. Forest will automatically
/// download the parameter files from IPFS and verify their validity. For
/// consistency, Forest will prefer to download the files it's local data
/// directory. To this end, the `FIL_PROOFS_PARAMETER_CACHE` environment
/// variable is updated before the parameters are downloaded.
///
/// More information available here: <https://github.com/filecoin-project/rust-fil-proofs#parameter-file-location>
pub fn set_proofs_parameter_cache_dir_env(data_dir: &Path) {
    std::env::set_var(DIR_ENV, param_dir(data_dir));
}

/// Ensures the parameter files are downloaded to cache dir
pub async fn ensure_params_downloaded() -> anyhow::Result<()> {
    let data_dir = std::env::var(DIR_ENV).unwrap_or_default();
    if data_dir.is_empty() {
        anyhow::bail!("Proof parameter data dir is not set");
    }
    get_params_default(Path::new(&data_dir), SectorSizeOpt::Keys, false).await?;

    Ok(())
}

/// Get proofs parameters and all verification keys for a given sector size
/// given a parameter JSON manifest.
pub async fn get_params(
    data_dir: &Path,
    param_json: &str,
    storage_size: SectorSizeOpt,
    dry_run: bool,
) -> Result<(), anyhow::Error> {
    // Just print out the parameters download directory path and exit.
    if dry_run {
        println!("{}", param_dir(data_dir).to_string_lossy());
        return Ok(());
    }

    fs::create_dir_all(param_dir(data_dir)).await?;

    let params: ParameterMap = serde_json::from_str(param_json)?;
    let mut tasks = Vec::with_capacity(params.len());

    params
        .into_iter()
        .filter(|(name, info)| match storage_size {
            SectorSizeOpt::Keys => !name.ends_with("params"),
            SectorSizeOpt::Size(size) => {
                size as u64 == info.sector_size || !name.ends_with(".params")
            }
            SectorSizeOpt::All => true,
        })
        .for_each(|(name, info)| {
            let data_dir_clone = data_dir.to_owned();
            tasks.push(tokio::task::spawn(async move {
                fetch_verify_params(&data_dir_clone, &name, Arc::new(info))
                    .await
                    .map_err(|err| {
                        error!("Error fetching param file {name}: {err}");
                        err
                    })
            }))
        });

    let mut errors = Vec::<anyhow::Error>::new();

    for t in tasks {
        match t.await {
            Err(err) => errors.push(err.into()),
            Ok(Err(err)) => errors.push(err),
            _ => (),
        }
    }

    if !errors.is_empty() {
        let error_messages: Vec<_> = errors.iter().map(|e| format!("{e}")).collect();
        anyhow::bail!(anyhow::Error::msg(format!(
            "Aggregated errors:\n{}",
            error_messages.join("\n\n")
        )))
    }

    Ok(())
}

/// Get proofs parameters and all verification keys for a given sector size
/// using default manifest.
#[inline]
pub async fn get_params_default(
    data_dir: &Path,
    storage_size: SectorSizeOpt,
    dry_run: bool,
) -> Result<(), anyhow::Error> {
    get_params(data_dir, DEFAULT_PARAMETERS, storage_size, dry_run).await
}

async fn fetch_verify_params(
    data_dir: &Path,
    name: &str,
    info: Arc<ParameterData>,
) -> Result<(), anyhow::Error> {
    let path: PathBuf = param_dir(data_dir).join(name);

    match check_file(&path, &info).await {
        Ok(()) => return Ok(()),
        Err(e) => {
            if e.kind() != ErrorKind::NotFound {
                warn!("Error checking file: {}", e);
            }
        }
    }

    fetch_params(&path, &info).await?;

    check_file(&path, &info).await?;
    Ok(())
}

async fn fetch_params(path: &Path, info: &ParameterData) -> anyhow::Result<()> {
    let cid = Cid::from_str(&info.cid)?;
    let gw = std::env::var(GATEWAY_ENV).unwrap_or_else(|_| GATEWAY.to_owned());
    info!("Fetching param file {} from {gw}", path.display());
    let backoff = ExponentialBackoffBuilder::default()
        // Up to 30 minutes for downloading the file. This may be drastic,
        // but the gateway proved to be unreliable at times and we
        // don't want to get stuck here. Better to fail fast and retry.
        .with_max_elapsed_time(Some(Duration::from_secs(60 * 30)))
        .build();
    let result = retry(backoff, || async {
        Ok(download_ipfs_file_trustlessly(&cid, Some(GATEWAY), path).await?)
    })
    .await;
    debug!("Done fetching param file {:?} from {}", path, gw);
    result
}

async fn check_file(path: &Path, info: &ParameterData) -> Result<(), io::Error> {
    if std::env::var(TRUST_PARAMS_ENV) == Ok("1".to_owned()) {
        warn!("Assuming parameter files are okay. Do not use in production!");
        return Ok(());
    }

    let hash = tokio::task::spawn_blocking({
        let file = SyncFile::open(path)?;
        move || -> Result<Hash, io::Error> {
            let mut reader = SyncBufReader::new(file);
            let mut hasher = Blake2b::new();
            sync_copy(&mut reader, &mut hasher)?;
            Ok(hasher.finalize())
        }
    })
    .await??;

    let str_sum = hash.to_hex();
    let str_sum = &str_sum[..32];
    if str_sum == info.digest {
        debug!("Parameter file {:?} is ok", path);
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Checksum mismatch in param file {:?}. ({} != {})",
            path, str_sum, info.digest
        )))
    }
}
