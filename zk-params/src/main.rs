// Copyright (c) 2025 ADnet Contributors
// SPDX-License-Identifier: Apache-2.0

//! ZK Parameters CDN Service for ADnet
//!
//! Serves zero-knowledge proving and verification keys for ALPHA chain.
//! Supports mainnet, testnet, and canary networks.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::fs;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "zk-params-server")]
#[command(about = "ZK Parameters CDN service for ADnet")]
struct Args {
    /// Directory containing ZK parameter files
    #[arg(short, long, env = "ZK_PARAMS_DIR", default_value = "./params")]
    params_dir: PathBuf,

    /// Address to bind the server to
    #[arg(short, long, env = "ZK_PARAMS_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Clone)]
struct AppState {
    params_dir: PathBuf,
}

/// Supported networks
const NETWORKS: &[&str] = &["mainnet", "testnet", "canary"];

/// Known parameter file types with their expected patterns
const PARAM_TYPES: &[&str] = &[
    "powers-of-beta", // Powers of tau ceremony output
    "shifted-powers", // Shifted powers for KZG
    "proving-key",    // Circuit-specific proving keys
    "verifying-key",  // Circuit-specific verification keys
    "universal-srs",  // Universal structured reference string
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Validate params directory
    if !args.params_dir.exists() {
        warn!("Parameters directory does not exist: {:?}", args.params_dir);
        warn!("Creating directory structure...");
        for network in NETWORKS {
            let network_dir = args.params_dir.join(network);
            fs::create_dir_all(&network_dir).await?;
            info!("Created: {:?}", network_dir);
        }
    }

    let state = AppState {
        params_dir: args.params_dir.clone(),
    };

    // Build router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/networks", get(list_networks))
        .route("/alpha/{network}", get(list_params))
        .route("/alpha/{network}/{filename}", get(serve_param))
        .route("/alpha/{network}/{filename}/checksum", get(get_checksum))
        .route("/alpha/{network}/{filename}/metadata", get(get_metadata))
        .layer(CompressionLayer::new())
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .layer(RequestBodyLimitLayer::new(1024)) // Limit request body size
        .with_state(Arc::new(state));

    info!("Starting ZK Parameters server on {}", args.bind);
    info!("Serving parameters from: {:?}", args.params_dir);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn list_networks() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "networks": NETWORKS,
        "service": "adnet-zk-params",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn list_params(
    State(state): State<Arc<AppState>>,
    Path(network): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Validate network
    if !NETWORKS.contains(&network.as_str()) {
        return Err(AppError::InvalidNetwork(network));
    }

    let network_dir = state.params_dir.join(&network);
    if !network_dir.exists() {
        return Ok(axum::Json(serde_json::json!({
            "network": network,
            "files": [],
        })));
    }

    let mut files = Vec::new();
    let mut entries = fs::read_dir(&network_dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            if let Some(filename) = path.file_name() {
                let metadata = entry.metadata().await?;
                files.push(serde_json::json!({
                    "name": filename.to_string_lossy(),
                    "size": metadata.len(),
                }));
            }
        }
    }

    Ok(axum::Json(serde_json::json!({
        "network": network,
        "files": files,
    })))
}

async fn serve_param(
    State(state): State<Arc<AppState>>,
    Path((network, filename)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Validate network
    if !NETWORKS.contains(&network.as_str()) {
        return Err(AppError::InvalidNetwork(network));
    }

    // Security: prevent path traversal
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(AppError::InvalidFilename(filename));
    }

    let file_path = state.params_dir.join(&network).join(&filename);

    if !file_path.exists() {
        return Err(AppError::FileNotFound(filename));
    }

    let metadata = fs::metadata(&file_path).await?;
    let file_size = metadata.len();

    // Handle range requests for large files
    if let Some(range_header) = headers.get("range") {
        return serve_range_request(&file_path, range_header, file_size).await;
    }

    // Serve full file
    let contents = fs::read(&file_path).await?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    response_headers.insert(
        "content-length",
        HeaderValue::from_str(&file_size.to_string()).unwrap(),
    );
    response_headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
    response_headers.insert(
        "content-disposition",
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename)).unwrap(),
    );

    Ok((StatusCode::OK, response_headers, contents).into_response())
}

async fn serve_range_request(
    file_path: &PathBuf,
    range_header: &HeaderValue,
    file_size: u64,
) -> Result<Response, AppError> {
    let range_str = range_header.to_str().map_err(|_| AppError::InvalidRange)?;

    // Parse "bytes=start-end" format
    if !range_str.starts_with("bytes=") {
        return Err(AppError::InvalidRange);
    }

    let range = &range_str[6..];
    let parts: Vec<&str> = range.split('-').collect();

    if parts.len() != 2 {
        return Err(AppError::InvalidRange);
    }

    let start: u64 = parts[0].parse().unwrap_or(0);
    let end: u64 = if parts[1].is_empty() {
        file_size - 1
    } else {
        parts[1].parse().unwrap_or(file_size - 1)
    };

    if start >= file_size || end >= file_size || start > end {
        return Err(AppError::InvalidRange);
    }

    let length = end - start + 1;

    // Read the specific range
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(file_path).await?;
    file.seek(std::io::SeekFrom::Start(start)).await?;

    let mut buffer = vec![0u8; length as usize];
    file.read_exact(&mut buffer).await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        "content-length",
        HeaderValue::from_str(&length.to_string()).unwrap(),
    );
    headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
    headers.insert(
        "content-range",
        HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, file_size)).unwrap(),
    );

    Ok((StatusCode::PARTIAL_CONTENT, headers, buffer).into_response())
}

async fn get_checksum(
    State(state): State<Arc<AppState>>,
    Path((network, filename)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    // Validate network
    if !NETWORKS.contains(&network.as_str()) {
        return Err(AppError::InvalidNetwork(network));
    }

    // Security: prevent path traversal
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(AppError::InvalidFilename(filename));
    }

    let file_path = state.params_dir.join(&network).join(&filename);

    if !file_path.exists() {
        return Err(AppError::FileNotFound(filename));
    }

    // Calculate SHA256 checksum
    let contents = fs::read(&file_path).await?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    let hash = hasher.finalize();
    let checksum = hex::encode(hash);

    Ok(axum::Json(serde_json::json!({
        "filename": filename,
        "network": network,
        "algorithm": "sha256",
        "checksum": checksum,
    })))
}

async fn get_metadata(
    State(state): State<Arc<AppState>>,
    Path((network, filename)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    // Validate network
    if !NETWORKS.contains(&network.as_str()) {
        return Err(AppError::InvalidNetwork(network));
    }

    // Security: prevent path traversal
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(AppError::InvalidFilename(filename));
    }

    let file_path = state.params_dir.join(&network).join(&filename);

    if !file_path.exists() {
        return Err(AppError::FileNotFound(filename));
    }

    let metadata = fs::metadata(&file_path).await?;

    // Determine param type from filename
    let param_type = PARAM_TYPES
        .iter()
        .find(|&&t| filename.contains(t))
        .unwrap_or(&"unknown");

    Ok(axum::Json(serde_json::json!({
        "filename": filename,
        "network": network,
        "size": metadata.len(),
        "param_type": param_type,
        "download_url": format!("/alpha/{}/{}", network, filename),
        "checksum_url": format!("/alpha/{}/{}/checksum", network, filename),
    })))
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("Invalid network: {0}. Valid networks: mainnet, testnet, canary")]
    InvalidNetwork(String),

    #[error("Invalid filename: {0}")]
    InvalidFilename(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Invalid range header")]
    InvalidRange,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::InvalidNetwork(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::InvalidFilename(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::FileNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::InvalidRange => (StatusCode::RANGE_NOT_SATISFIABLE, self.to_string()),
            AppError::Io(e) => {
                error!("IO error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
    }
}
