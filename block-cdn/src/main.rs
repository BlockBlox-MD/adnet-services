// Copyright (c) 2025 ADnet Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block CDN Service for ADnet
//!
//! Serves blockchain blocks for fast sync of ALPHA and DELTA chains.
//! Supports single block downloads, batch ranges, and block metadata queries.

use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::fs;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
};
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "block-cdn-server")]
#[command(about = "Block CDN service for ADnet")]
struct Args {
    /// Directory containing block data
    #[arg(short, long, env = "BLOCK_CDN_DIR", default_value = "./blocks")]
    blocks_dir: PathBuf,

    /// Address to bind the server to
    #[arg(short, long, env = "BLOCK_CDN_BIND", default_value = "0.0.0.0:8081")]
    bind: SocketAddr,

    /// Maximum blocks per batch request
    #[arg(long, env = "BLOCK_CDN_MAX_BATCH", default_value = "100")]
    max_batch: u32,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Clone)]
struct AppState {
    blocks_dir: PathBuf,
    max_batch: u32,
}

/// Supported chains
const CHAINS: &[&str] = &["alpha", "delta"];

/// Supported networks
const NETWORKS: &[&str] = &["mainnet", "testnet", "canary"];

/// Block file version (for format compatibility)
const BLOCK_FORMAT_VERSION: u32 = 0;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let level = if args.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Validate blocks directory
    if !args.blocks_dir.exists() {
        warn!("Blocks directory does not exist: {:?}", args.blocks_dir);
        warn!("Creating directory structure...");
        for chain in CHAINS {
            for network in NETWORKS {
                let block_dir = args.blocks_dir.join(chain).join(format!("v{}", BLOCK_FORMAT_VERSION)).join(network);
                fs::create_dir_all(&block_dir).await?;
                info!("Created: {:?}", block_dir);
            }
        }
    }

    let state = AppState {
        blocks_dir: args.blocks_dir.clone(),
        max_batch: args.max_batch,
    };

    // Build router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/chains", get(list_chains))
        .route("/{chain}/v{version}/{network}/latest", get(get_latest_height))
        .route("/{chain}/v{version}/{network}/blocks", get(list_blocks))
        .route("/{chain}/v{version}/{network}/blocks/{height}", get(get_block))
        .route("/{chain}/v{version}/{network}/blocks/{height}/checksum", get(get_block_checksum))
        .route("/{chain}/v{version}/{network}/range", get(get_block_range))
        .layer(CompressionLayer::new())
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .layer(RequestBodyLimitLayer::new(1024))
        .with_state(Arc::new(state));

    info!("Starting Block CDN server on {}", args.bind);
    info!("Serving blocks from: {:?}", args.blocks_dir);
    info!("Max batch size: {}", args.max_batch);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn list_chains() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "chains": CHAINS,
        "networks": NETWORKS,
        "current_version": BLOCK_FORMAT_VERSION,
        "service": "adnet-block-cdn",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Deserialize)]
struct BlocksQuery {
    offset: Option<u64>,
    limit: Option<u32>,
}

async fn list_blocks(
    State(state): State<Arc<AppState>>,
    Path((chain, version, network)): Path<(String, u32, String)>,
    Query(query): Query<BlocksQuery>,
) -> Result<impl IntoResponse, AppError> {
    validate_chain_network(&chain, &network)?;

    let blocks_dir = state.blocks_dir.join(&chain).join(format!("v{}", version)).join(&network);

    if !blocks_dir.exists() {
        return Ok(axum::Json(serde_json::json!({
            "chain": chain,
            "network": network,
            "version": version,
            "blocks": [],
            "total": 0,
        })));
    }

    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(1000);

    // Read directory and collect block heights
    let mut heights: Vec<u64> = Vec::new();
    let mut entries = fs::read_dir(&blocks_dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            if let Some(filename) = path.file_name() {
                let name = filename.to_string_lossy();
                // Parse height from filename (format: {height}.block)
                if let Some(height_str) = name.strip_suffix(".block") {
                    if let Ok(height) = height_str.parse::<u64>() {
                        heights.push(height);
                    }
                }
            }
        }
    }

    heights.sort();
    let total = heights.len();

    let blocks: Vec<u64> = heights
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    Ok(axum::Json(serde_json::json!({
        "chain": chain,
        "network": network,
        "version": version,
        "blocks": blocks,
        "total": total,
        "offset": offset,
        "limit": limit,
    })))
}

async fn get_latest_height(
    State(state): State<Arc<AppState>>,
    Path((chain, version, network)): Path<(String, u32, String)>,
) -> Result<impl IntoResponse, AppError> {
    validate_chain_network(&chain, &network)?;

    let blocks_dir = state.blocks_dir.join(&chain).join(format!("v{}", version)).join(&network);

    if !blocks_dir.exists() {
        return Ok(axum::Json(serde_json::json!({
            "chain": chain,
            "network": network,
            "version": version,
            "latest_height": null,
        })));
    }

    // Find highest block height
    let mut max_height: Option<u64> = None;
    let mut entries = fs::read_dir(&blocks_dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            if let Some(filename) = path.file_name() {
                let name = filename.to_string_lossy();
                if let Some(height_str) = name.strip_suffix(".block") {
                    if let Ok(height) = height_str.parse::<u64>() {
                        max_height = Some(max_height.map_or(height, |h| h.max(height)));
                    }
                }
            }
        }
    }

    Ok(axum::Json(serde_json::json!({
        "chain": chain,
        "network": network,
        "version": version,
        "latest_height": max_height,
    })))
}

async fn get_block(
    State(state): State<Arc<AppState>>,
    Path((chain, version, network, height)): Path<(String, u32, String, u64)>,
) -> Result<Response, AppError> {
    validate_chain_network(&chain, &network)?;

    let block_path = state.blocks_dir
        .join(&chain)
        .join(format!("v{}", version))
        .join(&network)
        .join(format!("{}.block", height));

    if !block_path.exists() {
        return Err(AppError::BlockNotFound(height));
    }

    let contents = fs::read(&block_path).await?;
    let file_size = contents.len();

    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/octet-stream"));
    headers.insert("content-length", HeaderValue::from_str(&file_size.to_string()).unwrap());
    headers.insert("x-block-height", HeaderValue::from_str(&height.to_string()).unwrap());
    headers.insert("x-block-chain", HeaderValue::from_str(&chain).unwrap());
    headers.insert("x-block-network", HeaderValue::from_str(&network).unwrap());
    headers.insert(
        "content-disposition",
        HeaderValue::from_str(&format!("attachment; filename=\"{}.block\"", height)).unwrap(),
    );

    Ok((StatusCode::OK, headers, contents).into_response())
}

async fn get_block_checksum(
    State(state): State<Arc<AppState>>,
    Path((chain, version, network, height)): Path<(String, u32, String, u64)>,
) -> Result<impl IntoResponse, AppError> {
    validate_chain_network(&chain, &network)?;

    let block_path = state.blocks_dir
        .join(&chain)
        .join(format!("v{}", version))
        .join(&network)
        .join(format!("{}.block", height));

    if !block_path.exists() {
        return Err(AppError::BlockNotFound(height));
    }

    let contents = fs::read(&block_path).await?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    let hash = hasher.finalize();
    let checksum = hex::encode(hash);

    Ok(axum::Json(serde_json::json!({
        "chain": chain,
        "network": network,
        "version": version,
        "height": height,
        "algorithm": "sha256",
        "checksum": checksum,
        "size": contents.len(),
    })))
}

#[derive(Deserialize)]
struct RangeQuery {
    start: u64,
    end: u64,
}

async fn get_block_range(
    State(state): State<Arc<AppState>>,
    Path((chain, version, network)): Path<(String, u32, String)>,
    Query(query): Query<RangeQuery>,
) -> Result<impl IntoResponse, AppError> {
    validate_chain_network(&chain, &network)?;

    let range_size = query.end.saturating_sub(query.start) + 1;
    if range_size > state.max_batch as u64 {
        return Err(AppError::RangeTooLarge(state.max_batch));
    }

    let blocks_dir = state.blocks_dir
        .join(&chain)
        .join(format!("v{}", version))
        .join(&network);

    let mut blocks = Vec::new();
    let mut missing = Vec::new();

    for height in query.start..=query.end {
        let block_path = blocks_dir.join(format!("{}.block", height));
        if block_path.exists() {
            let contents = fs::read(&block_path).await?;
            let mut hasher = Sha256::new();
            hasher.update(&contents);
            let checksum = hex::encode(hasher.finalize());

            blocks.push(serde_json::json!({
                "height": height,
                "size": contents.len(),
                "checksum": checksum,
                "download_url": format!("/{}/v{}/{}/blocks/{}", chain, version, network, height),
            }));
        } else {
            missing.push(height);
        }
    }

    Ok(axum::Json(serde_json::json!({
        "chain": chain,
        "network": network,
        "version": version,
        "range": {
            "start": query.start,
            "end": query.end,
        },
        "blocks": blocks,
        "missing": missing,
        "found": blocks.len(),
        "total_requested": range_size,
    })))
}

fn validate_chain_network(chain: &str, network: &str) -> Result<(), AppError> {
    if !CHAINS.contains(&chain) {
        return Err(AppError::InvalidChain(chain.to_string()));
    }
    if !NETWORKS.contains(&network) {
        return Err(AppError::InvalidNetwork(network.to_string()));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("Invalid chain: {0}. Valid chains: alpha, delta")]
    InvalidChain(String),

    #[error("Invalid network: {0}. Valid networks: mainnet, testnet, canary")]
    InvalidNetwork(String),

    #[error("Block not found at height: {0}")]
    BlockNotFound(u64),

    #[error("Range too large. Maximum: {0} blocks")]
    RangeTooLarge(u32),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::InvalidChain(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::InvalidNetwork(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::BlockNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::RangeTooLarge(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Io(e) => {
                error!("IO error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
    }
}
