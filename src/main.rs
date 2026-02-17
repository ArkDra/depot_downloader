mod manifest;
use crate::manifest::*;
use aes::{
    Aes256,
    cipher::{
        BlockDecryptMut, KeyInit, KeyIvInit, block_padding::Pkcs7, generic_array::GenericArray,
    },
};
use clap::{Parser, Subcommand};
use data_encoding::{BASE64_MIME, HEXLOWER};
use futures::stream::{self, TryStreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use liblzma::stream::{Action::Run, Filters, Stream};
use protobuf::Message;
use reqwest::{Client, Proxy};
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{BufReader, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::{
    sync::mpsc,
    task::spawn_blocking,
    time::{Duration, sleep},
};

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Protobuf(#[from] protobuf::Error),
    #[error(transparent)]
    Decode(#[from] data_encoding::DecodeError),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[error(transparent)]
    IndicatifTemplate(#[from] indicatif::style::TemplateError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
    #[error("{0}")]
    Message(String),
}

type Error = AppError;
#[cfg(windows)]
const INVALID_CHARS: &[char] = &['/', ':', '*', '?', '"', '<', '>', '|'];
#[cfg(not(windows))]
const INVALID_CHARS: &[char] = &['/'];

static NEXT_URL_INDEX: AtomicUsize = AtomicUsize::new(0);
static MONOTONIC_START: OnceLock<Instant> = OnceLock::new();

const MAGIC_LZMA: [u8; 3] = [86, 90, 97]; // "VZa"
const MAGIC_ZSTD: [u8; 4] = [86, 83, 90, 97]; // "VSZa"
const MAGIC_ZIP: [u8; 4] = [80, 75, 3, 4]; // "PK\x03\x04"
const INITIAL_BACKOFF_MS: u64 = 100;
const MAX_BACKOFF_MS: u64 = 2_000;
const EWMA_ALPHA_PERMILLE: u32 = 200;
const CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 3;
const CIRCUIT_BREAKER_BASE_COOLDOWN_MS: u64 = 1_500;

#[derive(Parser)]
struct Args {
    #[arg(short = 'm', long, required = true)]
    manifest_path: String,
    #[arg(short = 'k', long, required = true)]
    depot_key: String,
    #[arg(short = 'o', long, default_value = "default")]
    output_path: String,
    #[arg(short = 'p', long)]
    proxy_url: Option<String>,
    #[arg(short = 'r', long, default_value = "3")]
    retry_num: u32,
    #[arg(short = 'f', long, num_args = 1.., value_delimiter = ',')]
    file_names: Option<Vec<String>>,
    #[command(subcommand)]
    command: Option<Commands>,
}

struct AppConfig<'a> {
    manifest_path: &'a str,
    depot_key: &'a str,
    output_path: &'a str,
    proxy_url: Option<&'a str>,
    retry_num: u32,
    cdn_pairs: Option<Vec<(String, String)>>,
    file_names: Option<&'a [String]>,
}

impl Args {
    pub fn get_args(&self) -> Result<AppConfig<'_>, Error> {
        let cdn_pairs = match &self.command {
            Some(Commands::Cdn {
                cdn_url,
                cdn_url_suffix,
            }) => {
                if let Some(cdn_url_suffix) = cdn_url_suffix {
                    if cdn_url_suffix.len() > cdn_url.len() {
                        return Err(Error::Message(
                            "The number of cdn_url_suffix cannot be greater than cdn_url"
                                .to_string(),
                        ));
                    }
                    Some(
                        cdn_url
                            .iter()
                            .cloned()
                            .zip(
                                cdn_url_suffix
                                    .iter()
                                    .cloned()
                                    .chain(std::iter::repeat_n(
                                        "".to_string(),
                                        cdn_url.len() - cdn_url_suffix.len(),
                                    )),
                            )
                            .collect(),
                    )
                } else {
                    Some(
                        cdn_url
                            .iter()
                            .cloned()
                            .zip(std::iter::repeat_n("".to_string(), cdn_url.len()))
                            .collect(),
                    )
                }
            }
            None => None,
        };
        Ok(AppConfig {
            manifest_path: &self.manifest_path,
            depot_key: &self.depot_key,
            output_path: &self.output_path,
            proxy_url: self.proxy_url.as_deref(),
            retry_num: self.retry_num,
            cdn_pairs,
            file_names: self.file_names.as_deref(),
        })
    }
}

#[derive(Subcommand)]
enum Commands {
    Cdn {
        #[arg(short = 'u', long, num_args = 1.., value_delimiter = ',')]
        cdn_url: Vec<String>,
        #[arg(short = 's', long, num_args = 1.., value_delimiter = ',')]
        cdn_url_suffix: Option<Vec<String>>,
    },
}

struct ChunkInfo {
    offset: u64,
    original_size: u32,
    depot_id: u32,
    file_path: PathBuf,
    content_sha: String,
}

struct DownloadedChunk {
    chunk_info: ChunkInfo,
    data: Vec<u8>,
}

struct FileHandleState {
    file: File,
    remaining_chunks: usize,
}

struct CdnNodeStats {
    inflight: AtomicU32,
    ewma_throughput_kib_s: AtomicU32,
    ewma_fail_rate_permille: AtomicU32,
    consecutive_failures: AtomicU32,
    cooldown_until_ms: AtomicU64,
}

impl CdnNodeStats {
    fn new() -> Self {
        Self {
            inflight: AtomicU32::new(0),
            ewma_throughput_kib_s: AtomicU32::new(1_024),
            ewma_fail_rate_permille: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            cooldown_until_ms: AtomicU64::new(0),
        }
    }
}

struct CdnHealth {
    nodes: Vec<CdnNodeStats>,
}

fn monotonic_now_ms() -> u64 {
    MONOTONIC_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis() as u64
}

fn ewma_update_u32(old: u32, sample: u32) -> u32 {
    const EWMA_SCALE_PERMILLE: u64 = 1_000;
    let old_u64 = old as u64;
    let sample_u64 = sample as u64;
    let alpha = EWMA_ALPHA_PERMILLE as u64;
    let blended = (old_u64.saturating_mul(EWMA_SCALE_PERMILLE.saturating_sub(alpha)))
        .saturating_add(sample_u64.saturating_mul(alpha))
        / EWMA_SCALE_PERMILLE;
    blended.min(u32::MAX as u64) as u32
}

impl CdnHealth {
    fn new(host_count: usize) -> Self {
        let mut nodes = Vec::with_capacity(host_count);
        for _ in 0..host_count {
            nodes.push(CdnNodeStats::new());
        }
        Self { nodes }
    }

    fn on_request_start(&self, index: usize) {
        if let Some(node) = self.nodes.get(index) {
            node.inflight.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn mark_failure(&self, index: usize) {
        if let Some(node) = self.nodes.get(index) {
            let _ = node
                .inflight
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(1))
                });

            let old_fail_rate = node.ewma_fail_rate_permille.load(Ordering::Relaxed);
            node.ewma_fail_rate_permille
                .store(ewma_update_u32(old_fail_rate, 1_000), Ordering::Relaxed);

            let failure_streak = match node.consecutive_failures.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |value| Some(value.saturating_add(1)),
            ) {
                Ok(previous) => previous.saturating_add(1),
                Err(previous) => previous.saturating_add(1),
            };
            if failure_streak >= CIRCUIT_BREAKER_FAILURE_THRESHOLD {
                let exponent = (failure_streak - CIRCUIT_BREAKER_FAILURE_THRESHOLD).min(6);
                let cooldown_ms = CIRCUIT_BREAKER_BASE_COOLDOWN_MS
                    .checked_shl(exponent)
                    .unwrap_or(u64::MAX)
                    .min(CIRCUIT_BREAKER_BASE_COOLDOWN_MS.saturating_mul(10));
                let open_until = monotonic_now_ms().saturating_add(cooldown_ms);
                let _ = node.cooldown_until_ms.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |existing| Some(existing.max(open_until)),
                );
            }
        }
    }

    fn mark_success(&self, index: usize, bytes: usize, elapsed_ms: u64) {
        if let Some(node) = self.nodes.get(index) {
            let _ = node
                .inflight
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(1))
                });

            node.consecutive_failures.store(0, Ordering::Relaxed);
            node.cooldown_until_ms.store(0, Ordering::Relaxed);

            let old_fail_rate = node.ewma_fail_rate_permille.load(Ordering::Relaxed);
            node.ewma_fail_rate_permille
                .store(ewma_update_u32(old_fail_rate, 0), Ordering::Relaxed);

            let elapsed = elapsed_ms.max(1);
            let throughput_kib_s = ((bytes as u64).saturating_mul(1_000) / elapsed / 1_024)
                .max(1)
                .min(u32::MAX as u64) as u32;
            let old_throughput = node.ewma_throughput_kib_s.load(Ordering::Relaxed);
            node.ewma_throughput_kib_s.store(
                ewma_update_u32(old_throughput, throughput_kib_s),
                Ordering::Relaxed,
            );
        }
    }

    fn pick_candidate(seed: usize, len: usize, avoid: Option<usize>) -> usize {
        let mut candidate = seed % len;
        if let Some(avoid_idx) = avoid
            && len > 1
            && candidate == avoid_idx
        {
            candidate = (candidate + 1) % len;
        }
        candidate
    }

    fn score_candidate(&self, index: usize, now_ms: u64, avoid: Option<usize>) -> u64 {
        const FAIL_RATE_WEIGHT: u64 = 25;
        const INFLIGHT_WEIGHT: u64 = 500;
        const THROUGHPUT_BASE: u64 = 250_000;
        const CIRCUIT_OPEN_PENALTY: u64 = 1_000_000;
        const RETRY_SAME_HOST_PENALTY: u64 = 500_000;

        let Some(node) = self.nodes.get(index) else {
            return u64::MAX;
        };

        let inflight = node.inflight.load(Ordering::Relaxed) as u64;
        let throughput_kib_s = node.ewma_throughput_kib_s.load(Ordering::Relaxed).max(1) as u64;
        let fail_rate_permille = node.ewma_fail_rate_permille.load(Ordering::Relaxed) as u64;
        let cooldown_until = node.cooldown_until_ms.load(Ordering::Relaxed);

        let mut score = fail_rate_permille.saturating_mul(FAIL_RATE_WEIGHT);
        score = score.saturating_add(inflight.saturating_mul(INFLIGHT_WEIGHT));
        score = score.saturating_add(THROUGHPUT_BASE / throughput_kib_s);

        if cooldown_until > now_ms {
            score = score.saturating_add(CIRCUIT_OPEN_PENALTY);
        }

        if let Some(avoid_idx) = avoid
            && avoid_idx == index
        {
            score = score.saturating_add(RETRY_SAME_HOST_PENALTY);
        }

        score
    }

    fn pick_best_index(&self, seed: usize, avoid: Option<usize>) -> usize {
        let len = self.nodes.len();
        if len <= 1 {
            return 0;
        }

        let first = Self::pick_candidate(seed, len, avoid);
        let second_seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let mut second = Self::pick_candidate(second_seed, len, avoid);
        if first == second {
            second = (second + 1) % len;
            if let Some(avoid_idx) = avoid
                && len > 1
                && second == avoid_idx
            {
                second = (second + 1) % len;
            }
        }

        let now_ms = monotonic_now_ms();
        let first_score = self.score_candidate(first, now_ms, avoid);
        let second_score = self.score_candidate(second, now_ms, avoid);
        if first_score < second_score {
            first
        } else if second_score < first_score {
            second
        } else if self.nodes[first].inflight.load(Ordering::Relaxed)
            <= self.nodes[second].inflight.load(Ordering::Relaxed)
        {
            first
        } else {
            second
        }
    }
}

impl ChunkInfo {
    pub fn new(
        offset: u64,
        original_size: u32,
        depot_id: u32,
        file_path: PathBuf,
        content_sha: String,
    ) -> Self {
        ChunkInfo {
            offset,
            original_size,
            depot_id,
            file_path,
            content_sha,
        }
    }

    pub async fn get_chunk(
        &self,
        cdn_url_list: &[String],
        client: &Client,
        retry_num: u32,
        cdn_url_suffix_list: &[String],
        cdn_health: &CdnHealth,
    ) -> Result<Vec<u8>, Error> {
        let url_list_len = cdn_url_list.len();
        if url_list_len == 0 || url_list_len != cdn_url_suffix_list.len() {
            return Err(Error::Message(format!(
                "Invalid CDN URL/suffix configuration: urls={}, suffixes={}",
                url_list_len,
                cdn_url_suffix_list.len()
            )));
        }

        let mut retry_count = 0;
        let max_attempts = retry_num.saturating_add(1);
        let mut backoff_ms = INITIAL_BACKOFF_MS;
        let mut last_error: Option<String> = None;
        let mut last_index: Option<usize> = None;

        loop {
            let selection_seed = NEXT_URL_INDEX
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(retry_count as usize);
            let avoid_index = if retry_count == 0 { None } else { last_index };
            let index = cdn_health.pick_best_index(selection_seed, avoid_index);
            let url = format!(
                "http://{}/depot/{}/chunk/{}{}",
                &cdn_url_list[index], self.depot_id, self.content_sha, &cdn_url_suffix_list[index]
            );
            let started_at = Instant::now();
            cdn_health.on_request_start(index);

            let request_result = match client.get(&url).send().await {
                Ok(res) => match res.error_for_status() {
                    Ok(ok_res) => ok_res
                        .bytes()
                        .await
                        .map_err(|e| format!("failed to read response body from {url}: {e}")),
                    Err(e) => Err(format!("http status error from {url}: {e}")),
                },
                Err(e) => Err(format!("request error for {url}: {e}")),
            };

            let elapsed_ms = started_at.elapsed().as_millis().max(1) as u64;
            match request_result {
                Ok(body_data) => {
                    if !body_data.is_empty() {
                        cdn_health.mark_success(index, body_data.len(), elapsed_ms);
                        return Ok(body_data.to_vec());
                    }
                    if last_error.is_none() {
                        last_error = Some(format!("empty response body from {url}"));
                    }
                    cdn_health.mark_failure(index);
                }
                Err(err_message) => {
                    if last_error.is_none() {
                        last_error = Some(err_message);
                    }
                    cdn_health.mark_failure(index);
                }
            }

            last_index = Some(index);
            retry_count += 1;
            if retry_count < max_attempts {
                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2).min(MAX_BACKOFF_MS);
            } else {
                return Err(Error::Message(format!(
                    "Failed to download chunk {} after {} attempts: {}",
                    self.content_sha,
                    max_attempts,
                    last_error.unwrap_or_else(|| "unknown error".to_string())
                )));
            }
        }
    }
}

struct Manifest {
    manifest_content: Vec<u8>,
}
impl Manifest {
    pub fn new(manifest_path: &str) -> Result<Self, Error> {
        let file = std::fs::File::open(manifest_path)?;
        let mut bufreader = BufReader::new(file);
        let mut manifest_content = Vec::new();
        bufreader.read_to_end(&mut manifest_content)?;
        Ok(Manifest { manifest_content })
    }

    pub fn deserialize_manifest(
        &self,
    ) -> Result<(ContentManifestPayload, ContentManifestMetadata), Error> {
        let mut cursor = Cursor::new(&self.manifest_content);
        let mut payload_length = [0u8; 4];
        std::io::Cursor::seek(&mut cursor, SeekFrom::Start(4))?;
        cursor.read_exact(&mut payload_length)?;
        let payload_length = u32::from_le_bytes(payload_length);
        let mut payload = vec![0u8; payload_length as usize];
        cursor.read_exact(&mut payload)?;
        std::io::Cursor::seek(&mut cursor, SeekFrom::Current(4))?;
        let mut metadata_length = [0u8; 4];
        cursor.read_exact(&mut metadata_length)?;
        let metadata_length = u32::from_le_bytes(metadata_length);
        let mut metadata = vec![0u8; metadata_length as usize];
        cursor.read_exact(&mut metadata)?;
        let payload = ContentManifestPayload::parse_from_bytes(&payload)?;
        let metadata = ContentManifestMetadata::parse_from_bytes(&metadata)?;
        Ok((payload, metadata))
    }
}

struct Decrypt<'a> {
    key: &'a [u8],
    encrypted_data: Vec<u8>,
}
impl<'a> Decrypt<'a> {
    pub fn new(encrypted_data: Vec<u8>, key: &'a [u8]) -> Self {
        Decrypt {
            key,
            encrypted_data,
        }
    }

    pub fn decrypt_chunk(&mut self) -> Result<Vec<u8>, Error> {
        if self.encrypted_data.len() < 16 {
            return Err(Error::Message("Encrypted chunk is too short".to_string()));
        }

        let mut iv_block = GenericArray::clone_from_slice(&self.encrypted_data[..16]);
        let mut ecb_cipher = ecb::Decryptor::<Aes256>::new_from_slice(self.key)
            .map_err(|e| Error::Message(format!("Invalid key length: {e:?}")))?;
        ecb_cipher.decrypt_block_mut(&mut iv_block);

        let cbc_cipher = cbc::Decryptor::<Aes256>::new_from_slices(self.key, iv_block.as_slice())
            .map_err(|e| Error::Message(format!("Invalid key or IV: {e:?}")))?;

        let decrypted_len = {
            let encrypted_payload = &mut self.encrypted_data[16..];
            let decrypted_slice = cbc_cipher
                .decrypt_padded_mut::<Pkcs7>(encrypted_payload)
                .map_err(|e| Error::Message(format!("Unpadding error: {e:?}")))?;
            decrypted_slice.len()
        };

        self.encrypted_data.copy_within(16..16 + decrypted_len, 0);
        self.encrypted_data.truncate(decrypted_len);
        Ok(std::mem::take(&mut self.encrypted_data))
    }

    pub fn decrypt_file_name(&mut self) -> Result<String, Error> {
        let file_name = String::from_utf8(self.decrypt_chunk()?)?;
        Ok(file_name
            .chars()
            .filter(|c| !c.is_control() && !INVALID_CHARS.contains(c))
            .collect::<String>())
    }
}

fn set_client(proxy_url: Option<&str>) -> Result<Client, Error> {
    match proxy_url {
        Some(proxy_url) => Ok(reqwest::ClientBuilder::new()
            .use_native_tls()
            .tcp_keepalive(Duration::from_secs(20))
            .timeout(Duration::from_secs(30))
            .proxy(Proxy::all(proxy_url)?)
            .build()?),
        None => Ok(reqwest::ClientBuilder::new()
            .use_native_tls()
            .tcp_keepalive(Duration::from_secs(20))
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .build()?),
    }
}

async fn get_cdn_url_list(client: &Client) -> Result<Vec<String>, Error> {
    let url =
        "https://api.steampowered.com/icontentserverdirectoryservice/getserversforsteampipe/v1";
    let response = client.get(url).send().await?;
    let text = response.text().await?;
    let json_data: Value = serde_json::from_str(&text)?;
    let servers = json_data["response"]["servers"]
        .as_array()
        .ok_or_else(|| Error::Message("servers not found".to_string()))?;

    let mut strict = Vec::new();
    let mut relaxed = Vec::new();
    let mut seen = HashSet::new();
    for server in servers {
        let host = match server["host"].as_str() {
            Some(h) if !h.is_empty() => h,
            _ => continue,
        };
        if !host.contains("steamcontent.com") {
            continue;
        }
        if !seen.insert(host.to_string()) {
            continue;
        }

        let weighted_load = server["weighted_load"].as_i64().unwrap_or(i64::MAX);
        if weighted_load <= 130 && host.contains("steampipe") {
            strict.push(host.to_string());
        } else {
            relaxed.push(host.to_string());
        }
    }
    if !strict.is_empty() {
        return Ok(strict);
    }
    if !relaxed.is_empty() {
        return Ok(relaxed);
    }

    Err(Error::Message(
        "No available CDN hosts from Steam directory service. \
You can use the `cdn -u <host> -s <token>` mode or check network/proxy settings."
            .to_string(),
    ))
}

fn prepare_output_file(
    file_name: &str,
    file_sha: String,
    depot_id: u32,
    output_path: &str,
    file_size: u64,
) -> Result<(bool, PathBuf), Error> {
    let path = if output_path == "default" {
        let mut path_buf = std::env::current_dir()?;
        path_buf.push(depot_id.to_string());
        path_buf.push(file_name);
        path_buf
    } else {
        Path::new(output_path).join(file_name)
    };

    if path.exists() {
        let mut file = File::open(&path)?;
        let mut hasher = Sha1::default();
        let mut buffer = vec![0u8; 10485760];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let downloaded_file_sha = HEXLOWER.encode(&hasher.finalize());
        if file_sha == downloaded_file_sha {
            println!("{} already downloaded", file_name);
            return Ok((true, path));
        }
    } else {
        if let Some(parent_dir) = path.parent()
            && !parent_dir.exists()
        {
            fs::create_dir_all(parent_dir)?;
        }
        File::create(&path)?;
    }
    let file = std::fs::OpenOptions::new().write(true).open(&path)?;
    file.set_len(0)?;
    file.set_len(file_size)?;
    Ok((false, path))
}

fn decompress_into(compressed_data: &[u8], output: &mut Vec<u8>) -> Result<(), Error> {
    if compressed_data.len() < 4 {
        return Err(Error::Message(
            "Compressed chunk is too short for header".to_string(),
        ));
    }

    let mut header = [0u8; 4];
    header.copy_from_slice(&compressed_data[..4]);
    let compressed_data_len = compressed_data.len();
    output.clear();

    if header[..3] == MAGIC_LZMA {
        if compressed_data_len < 22 {
            return Err(Error::Message(
                "Compressed LZMA chunk is too short".to_string(),
            ));
        }

        let raw_data = &compressed_data[12..compressed_data_len - 10];
        let decrypted_size = u32::from_le_bytes(
            compressed_data[compressed_data_len - 6..compressed_data_len - 2]
                .try_into()
                .unwrap(),
        ) as usize;
        let crc = u32::from_le_bytes(
            compressed_data[compressed_data_len - 10..compressed_data_len - 6]
                .try_into()
                .unwrap(),
        );

        if output.capacity() < decrypted_size {
            output.reserve(decrypted_size - output.len());
        }

        let mut filter = Filters::new();
        filter
            .lzma1_properties(&compressed_data[7..12])
            .map_err(|e| Error::Message(format!("LZMA properties error: {e:?}")))?;
        Stream::new_raw_decoder(&filter)
            .map_err(|e| Error::Message(format!("LZMA decoder init error: {e:?}")))?
            .process_vec(raw_data, output, Run)
            .map_err(|e| Error::Message(format!("LZMA decode error: {e:?}")))?;

        if crc == crc32fast::hash(output) {
            Ok(())
        } else {
            Err(Error::Message(
                "decompressed lzma data CRC mismatch".to_string(),
            ))
        }
    } else if header == MAGIC_ZSTD {
        if compressed_data_len < 23 {
            return Err(Error::Message(
                "Compressed zstd chunk is too short".to_string(),
            ));
        }

        let raw_data = &compressed_data[8..compressed_data_len - 15];
        let decrypted_size = u32::from_le_bytes(
            compressed_data[compressed_data_len - 11..compressed_data_len - 7]
                .try_into()
                .unwrap(),
        ) as usize;
        let crc = u32::from_le_bytes(compressed_data[4..8].try_into().unwrap());

        if output.capacity() < decrypted_size {
            output.reserve(decrypted_size - output.len());
        }

        zstd::stream::copy_decode(raw_data, &mut *output)?;

        if crc == crc32fast::hash(output) {
            Ok(())
        } else {
            Err(Error::Message(
                "decompressed zstd data CRC mismatch".to_string(),
            ))
        }
    } else if header == MAGIC_ZIP {
        let raw_data = Cursor::new(compressed_data);

        let mut archive = zip::ZipArchive::new(raw_data)?;
        let mut file = archive.by_index(0)?;

        let crc = file.crc32();
        let decrypted_size = file.size() as usize;
        if output.capacity() < decrypted_size {
            output.reserve(decrypted_size - output.len());
        }
        file.read_to_end(output)?;

        if crc == crc32fast::hash(output) {
            Ok(())
        } else {
            Err(Error::Message(
                "decompressed zip data CRC mismatch".to_string(),
            ))
        }
    } else {
        Err(Error::Message("Unknown file format detected".to_string()))
    }
}

fn init_file_handles(
    file_chunk_counts: &HashMap<PathBuf, usize>,
) -> Result<HashMap<PathBuf, Arc<Mutex<FileHandleState>>>, Error> {
    let mut file_handles = HashMap::with_capacity(file_chunk_counts.len());

    for (path, chunk_count) in file_chunk_counts {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        file_handles.insert(
            path.clone(),
            Arc::new(Mutex::new(FileHandleState {
                file,
                remaining_chunks: *chunk_count,
            })),
        );
    }

    Ok(file_handles)
}

async fn download_chunks(
    all_chunks: Vec<ChunkInfo>,
    download_concurrency: usize,
    cdn_url_list: Arc<[String]>,
    cdn_url_suffix_list: Arc<[String]>,
    client: &Client,
    retry_num: u32,
    cdn_health: Arc<CdnHealth>,
    pb: &ProgressBar,
    tx: mpsc::Sender<DownloadedChunk>,
) -> Result<(), Error> {
    stream::iter(all_chunks.into_iter().map(Ok::<ChunkInfo, Error>))
        .try_for_each_concurrent(download_concurrency, |chunk_info| {
            let cdn_url_list_for_task = Arc::clone(&cdn_url_list);
            let cdn_url_suffix_list_for_task = Arc::clone(&cdn_url_suffix_list);
            let cdn_health_for_task = Arc::clone(&cdn_health);
            let tx_for_task = tx.clone();
            async move {
                let data = chunk_info
                    .get_chunk(
                        cdn_url_list_for_task.as_ref(),
                        client,
                        retry_num,
                        cdn_url_suffix_list_for_task.as_ref(),
                        cdn_health_for_task.as_ref(),
                    )
                    .await?;
                pb.inc(data.len() as u64);
                tx_for_task
                    .send(DownloadedChunk { chunk_info, data })
                    .await
                    .map_err(|_| {
                        Error::Message(
                            "Decode stage terminated before all downloads finished".to_string(),
                        )
                    })?;
                Ok::<(), Error>(())
            }
        })
        .await
}

async fn decode_and_write_chunks(
    rx: mpsc::Receiver<DownloadedChunk>,
    decode_concurrency: usize,
    depot_key: Arc<[u8]>,
    file_handles: Arc<HashMap<PathBuf, Arc<Mutex<FileHandleState>>>>,
) -> Result<(), Error> {
    let shared_rx = Arc::new(Mutex::new(rx));
    let mut workers = Vec::with_capacity(decode_concurrency);

    for _ in 0..decode_concurrency {
        let rx_for_worker = Arc::clone(&shared_rx);
        let depot_key_for_worker = Arc::clone(&depot_key);
        let file_handles_for_worker = Arc::clone(&file_handles);
        let worker = spawn_blocking(move || -> Result<(), Error> {
            loop {
                let downloaded_chunk = {
                    let mut guard = rx_for_worker
                        .lock()
                        .map_err(|_| Error::Message("Decode queue lock poisoned".to_string()))?;
                    guard.blocking_recv()
                };

                let Some(DownloadedChunk { chunk_info, data }) = downloaded_chunk else {
                    break;
                };

                let original_size = chunk_info.original_size;
                let mut decrypt = Decrypt::new(data, depot_key_for_worker.as_ref());
                let decrypted_data = decrypt.decrypt_chunk()?;
                let mut output = Vec::with_capacity(original_size as usize);
                decompress_into(&decrypted_data, &mut output)?;

                if output.len() != original_size as usize {
                    return Err(Error::Message(format!(
                        "Size mismatch: expected {} got {}",
                        original_size,
                        output.len()
                    )));
                }

                let file_handle = file_handles_for_worker
                    .get(&chunk_info.file_path)
                    .ok_or_else(|| {
                        Error::Message(format!(
                            "Missing file handle for {}",
                            chunk_info.file_path.display()
                        ))
                    })?;
                let mut file_state = file_handle.lock().map_err(|_| {
                    Error::Message(format!(
                        "File handle lock poisoned for {}",
                        chunk_info.file_path.display()
                    ))
                })?;
                file_state.file.seek(SeekFrom::Start(chunk_info.offset))?;
                file_state.file.write_all(&output)?;
                if file_state.remaining_chunks == 0 {
                    return Err(Error::Message(format!(
                        "Unexpected extra chunk write for {}",
                        chunk_info.file_path.display()
                    )));
                }
                file_state.remaining_chunks -= 1;
                if file_state.remaining_chunks == 0 {
                    file_state.file.flush()?;
                }
            }

            Ok(())
        });
        workers.push(worker);
    }

    for worker in workers {
        worker.await??;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let config = args.get_args()?;
    let decoded_depot_key: Arc<[u8]> = HEXLOWER.decode(config.depot_key.as_bytes())?.into();
    let normalized_file_names = config.file_names.map(|names| {
        names
            .iter()
            .map(|name| name.replace("\\", "/"))
            .collect::<HashSet<_>>()
    });

    let manifest = Manifest::new(config.manifest_path)?;
    let (payload, metadata) = Manifest::deserialize_manifest(&manifest)?;

    let client = set_client(config.proxy_url)?;

    let (cdn_url_list, cdn_url_suffix_list): (Arc<[String]>, Arc<[String]>) = match config.cdn_pairs
    {
        Some(pairs) => {
            let (urls, suffixes): (Vec<String>, Vec<String>) = pairs.into_iter().unzip();
            (urls.into(), suffixes.into())
        }
        None => {
            let urls = get_cdn_url_list(&client).await?;
            let urls_len = urls.len();
            (urls.into(), vec!["".to_string(); urls_len].into())
        }
    };

    let cpu_num = num_cpus::get();
    let download_concurrency = (cpu_num * 4).max(1);
    let decode_concurrency = cpu_num.max(1);
    let decode_queue_capacity = (decode_concurrency * 2).max(1);
    let mut all_chunks = Vec::new();
    let mut file_chunk_counts = HashMap::new();
    let mut estimated_download_bytes = 0;
    // Step 1: Preprocess all files to be downloaded
    for file in payload.mappings {
        if file.flags == 0 {
            let file_name = if metadata.filenames_encrypted {
                let decoded_file_name = BASE64_MIME.decode(file.filename.as_bytes())?;
                let mut decrypt = Decrypt::new(decoded_file_name, decoded_depot_key.as_ref());
                decrypt.decrypt_file_name()?
            } else {
                file.filename
            };

            if let Some(file_names) = normalized_file_names.as_ref() {
                let normalized_file_name = file_name.replace("\\", "/");
                if !file_names.contains(&normalized_file_name) {
                    continue;
                }
            }

            let file_sha = HEXLOWER.encode(&file.sha_content);
            let (is_exist, path) = prepare_output_file(
                &file_name,
                file_sha,
                metadata.depot_id,
                config.output_path,
                file.size,
            )?;
            if is_exist {
                continue;
            }

            let chunk_count = file.chunks.len();
            let mut file_chunks = Vec::with_capacity(file.chunks.len());
            // Step 2: Extract all chunk information
            for chunk in file.chunks {
                if chunk.cb_compressed != 0 {
                    estimated_download_bytes += chunk.cb_compressed as u64;
                }
                let chunk_info = ChunkInfo::new(
                    chunk.offset,
                    chunk.cb_original,
                    metadata.depot_id,
                    path.to_owned(),
                    HEXLOWER.encode(&chunk.sha),
                );
                file_chunks.push(chunk_info);
            }

            all_chunks.extend(file_chunks);
            if chunk_count != 0 {
                file_chunk_counts.insert(path, chunk_count);
            }
        }
    }

    let progress_style = ProgressStyle::with_template(
        "[{elapsed_precise}] [{bar}] {decimal_bytes}/{decimal_total_bytes} ({decimal_bytes_per_sec}, {eta})",
    )?
    .progress_chars("#>-");
    let pb = ProgressBar::new(estimated_download_bytes).with_style(progress_style);

    // Step 3: split into download stage and decode/write stage with bounded backpressure
    let (tx, rx) = mpsc::channel(decode_queue_capacity);
    let cdn_health = Arc::new(CdnHealth::new(cdn_url_list.len()));
    let file_handles = Arc::new(init_file_handles(&file_chunk_counts)?);

    tokio::try_join!(
        download_chunks(
            all_chunks,
            download_concurrency,
            Arc::clone(&cdn_url_list),
            Arc::clone(&cdn_url_suffix_list),
            &client,
            config.retry_num,
            Arc::clone(&cdn_health),
            &pb,
            tx,
        ),
        decode_and_write_chunks(rx, decode_concurrency, decoded_depot_key, file_handles),
    )?;

    Ok(())
}
