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
    collections::HashSet,
    fs::{self, File},
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
};
use tokio::{
    io::AsyncWriteExt,
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

const MAGIC_LZMA: [u8; 3] = [86, 90, 97]; // "VZa"
const MAGIC_ZSTD: [u8; 4] = [86, 83, 90, 97]; // "VSZa"
const MAGIC_ZIP: [u8; 4] = [80, 75, 3, 4]; // "PK\x03\x04"
const INITIAL_BACKOFF_MS: u64 = 100;
const MAX_BACKOFF_MS: u64 = 2_000;

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
    pub fn get_args(&self) -> AppConfig<'_> {
        let cdn_pairs = match &self.command {
            Some(Commands::Cdn {
                cdn_url,
                cdn_url_suffix,
            }) => {
                if let Some(cdn_url_suffix) = cdn_url_suffix {
                    if cdn_url.len() != cdn_url_suffix.len() {
                        panic!("The number of cdn_url and cdn_url_suffix must be the same");
                    }
                    Some(
                        cdn_url
                            .iter()
                            .cloned()
                            .zip(cdn_url_suffix.iter().cloned())
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
        AppConfig {
            manifest_path: &self.manifest_path,
            depot_key: &self.depot_key,
            output_path: &self.output_path,
            proxy_url: self.proxy_url.as_deref(),
            retry_num: self.retry_num,
            cdn_pairs,
            file_names: self.file_names.as_deref(),
        }
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

struct CdnHealth {
    scores: Vec<AtomicU32>,
}

impl CdnHealth {
    fn new(host_count: usize) -> Self {
        let mut scores = Vec::with_capacity(host_count);
        for _ in 0..host_count {
            scores.push(AtomicU32::new(0));
        }
        Self { scores }
    }

    fn mark_failure(&self, index: usize) {
        if let Some(score) = self.scores.get(index) {
            let _ = score.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(2))
            });
        }
    }

    fn mark_success(&self, index: usize) {
        if let Some(score) = self.scores.get(index) {
            let _ = score.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            });
        }
    }

    fn pick_best_index(&self, seed: usize) -> usize {
        let len = self.scores.len();
        if len == 0 {
            return 0;
        }

        let mut best_index = seed % len;
        let mut best_score = self.scores[best_index].load(Ordering::Relaxed);
        for offset in 1..len {
            let index = (seed + offset) % len;
            let score = self.scores[index].load(Ordering::Relaxed);
            if score < best_score {
                best_score = score;
                best_index = index;
            }
        }
        best_index
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
            return Err(Error::Message(
                "Invalid CDN URL/suffix configuration.".to_string(),
            ));
        }

        let mut index = cdn_health.pick_best_index(NEXT_URL_INDEX.fetch_add(1, Ordering::Relaxed));
        let mut retry_count = 0;
        let mut backoff_ms = INITIAL_BACKOFF_MS;
        let mut last_error: Option<String> = None;

        loop {
            let url = format!(
                "http://{}/depot/{}/chunk/{}{}",
                &cdn_url_list[index], self.depot_id, self.content_sha, &cdn_url_suffix_list[index]
            );
            match client.get(&url).send().await {
                Ok(res) => match res.error_for_status() {
                    Ok(ok_res) => match ok_res.bytes().await {
                        Ok(body_data) => {
                            if !body_data.is_empty() {
                                cdn_health.mark_success(index);
                                return Ok(body_data.to_vec());
                            }
                            if last_error.is_none() {
                                last_error = Some(format!("empty response body from {url}"));
                            }
                            cdn_health.mark_failure(index);
                        }
                        Err(e) => {
                            if last_error.is_none() {
                                last_error =
                                    Some(format!("failed to read response body from {url}: {e}"));
                            }
                            cdn_health.mark_failure(index);
                        }
                    },
                    Err(e) => {
                        if last_error.is_none() {
                            last_error = Some(format!("http status error from {url}: {e}"));
                        }
                        cdn_health.mark_failure(index);
                    }
                },
                Err(e) => {
                    if last_error.is_none() {
                        last_error = Some(format!("request error for {url}: {e}"));
                    }
                    cdn_health.mark_failure(index);
                }
            }

            retry_count += 1;
            if retry_count < retry_num {
                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2).min(MAX_BACKOFF_MS);
                index = cdn_health.pick_best_index(NEXT_URL_INDEX.fetch_add(1, Ordering::Relaxed));
            } else {
                return Err(Error::Message(format!(
                    "Failed to download chunk {} after {} attempts: {}",
                    self.content_sha,
                    retry_num,
                    last_error.unwrap_or_else(|| "unknown error".to_string())
                )));
            }
        }
    }

    pub async fn write_chunk_into_file(&self, decrypted_data: Vec<u8>) -> Result<(), Error> {
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.file_path)
            .await?;
        tokio::io::AsyncSeekExt::seek(&mut file, SeekFrom::Start(self.offset)).await?;
        file.write_all(&decrypted_data).await?;
        file.flush().await?;
        Ok(())
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

struct Decrypt {
    key: Vec<u8>,
    encrypted_data: Vec<u8>,
    iv: Vec<u8>,
}
impl Decrypt {
    pub fn new(encrypted_data: Vec<u8>) -> Self {
        Decrypt {
            key: vec![],
            encrypted_data,
            iv: vec![],
        }
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.key = key
    }

    fn set_iv(&mut self, iv: Vec<u8>) {
        self.iv = iv
    }

    fn ecb_decrypt(&self, iv: &[u8]) -> Result<Vec<u8>, Error> {
        let mut block = GenericArray::from_slice(iv).to_owned();
        let mut cipher = ecb::Decryptor::<Aes256>::new_from_slice(&self.key)
            .map_err(|e| Error::Message(format!("Invalid key length: {e:?}")))?;
        cipher.decrypt_block_mut(&mut block);
        let data = block.to_vec();
        Ok(data)
    }

    fn cbc_decrypt(&self, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let cipher = cbc::Decryptor::<Aes256>::new_from_slices(&self.key, &self.iv)
            .map_err(|e| Error::Message(format!("Invalid key or IV: {e:?}")))?;
        let decrypted_data = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .map_err(|e| Error::Message(format!("Unpadding error: {e:?}")))?;
        Ok(decrypted_data.to_vec())
    }

    pub fn decrypt_chunk(&mut self) -> Result<Vec<u8>, Error> {
        let decrypted_iv = self.ecb_decrypt(&self.encrypted_data[..16])?;
        self.set_iv(decrypted_iv);
        let data = self.encrypted_data[16..].to_vec();
        let decrypted_data = self.cbc_decrypt(data)?;
        Ok(decrypted_data)
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

    let mut url_list = Vec::new();
    for server in servers {
        if server["weighted_load"].as_i64() <= Some(130)
            && let Some(host) = server["host"].as_str()
            && host.contains("steamcontent.com") && host.contains("steampipe")
        {
            url_list.push(host.to_string());
        }
    }
    Ok(url_list)
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
        let file = File::create(&path)?;
        file.set_len(file_size)?
    }
    Ok((false, path))
}

fn decompress(compressed_data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut header = [0u8; 4];
    let data_header = &compressed_data[..4];
    header.clone_from_slice(data_header);
    let compressed_data_len = compressed_data.len();
    if header[..3] == MAGIC_LZMA {
        let raw_data = &compressed_data[12..compressed_data_len - 10];

        let decrypted_size_bytes =
            &compressed_data[compressed_data_len - 6..compressed_data_len - 2];
        let decrypted_size = u32::from_le_bytes(decrypted_size_bytes.try_into().unwrap());
        let mut decrypted_data = Vec::with_capacity(decrypted_size as usize);
        let crc_bytes = &compressed_data[compressed_data_len - 10..compressed_data_len - 6];
        let crc = u32::from_le_bytes(crc_bytes.try_into().unwrap());

        let mut filter = Filters::new();
        filter
            .lzma1_properties(&compressed_data[7..12])
            .map_err(|e| Error::Message(format!("LZMA properties error: {e:?}")))?;
        Stream::new_raw_decoder(&filter)
            .map_err(|e| Error::Message(format!("LZMA decoder init error: {e:?}")))?
            .process_vec(raw_data, &mut decrypted_data, Run)
            .map_err(|e| Error::Message(format!("LZMA decode error: {e:?}")))?;

        if crc == crc32fast::hash(&decrypted_data) {
            Ok(decrypted_data)
        } else {
            Err(Error::Message(
                "decompressed lzma data CRC mismatch".to_string(),
            ))
        }
    } else if header == MAGIC_ZSTD {
        let raw_data = &compressed_data[8..compressed_data_len - 15];

        let decrypted_size_bytes =
            &compressed_data[compressed_data_len - 11..compressed_data_len - 7];
        let decrypted_size = u32::from_le_bytes(decrypted_size_bytes.try_into().unwrap());
        let mut decrypted_data = Vec::with_capacity(decrypted_size as usize);
        let crc_bytes = &compressed_data[4..8];
        let crc = u32::from_le_bytes(crc_bytes.try_into().unwrap());

        zstd::stream::copy_decode(raw_data, &mut decrypted_data)?;

        if crc == crc32fast::hash(&decrypted_data) {
            Ok(decrypted_data)
        } else {
            Err(Error::Message(
                "decompressed zstd data CRC mismatch".to_string(),
            ))
        }
    } else if header == MAGIC_ZIP {
        let raw_data = Cursor::new(&compressed_data);

        let mut archive = zip::ZipArchive::new(raw_data)?;
        let mut file = archive.by_index(0)?;

        let crc = file.crc32();
        let decrypted_size = file.size() as usize;
        let mut decrypted_data = Vec::with_capacity(decrypted_size);

        file.read_to_end(&mut decrypted_data)?;

        if crc == crc32fast::hash(&decrypted_data) {
            Ok(decrypted_data)
        } else {
            Err(Error::Message(
                "decompressed zip data CRC mismatch".to_string(),
            ))
        }
    } else {
        Err(Error::Message("Unknown file format detected".to_string()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let config = args.get_args();
    let decoded_depot_key = HEXLOWER.decode(config.depot_key.as_bytes())?;
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
    let mut all_chunks = Vec::new();
    let mut estimated_download_bytes = 0;
    // Step 1: Preprocess all files to be downloaded
    for file in payload.mappings {
        if file.flags == 0 {
            let file_name = if metadata.filenames_encrypted {
                let decoded_file_name = BASE64_MIME.decode(file.filename.as_bytes())?;
                let mut decrypt = Decrypt::new(decoded_file_name);
                decrypt.set_key(decoded_depot_key.clone());
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
        }
    }

    let progress_style = ProgressStyle::with_template(
        "[{elapsed_precise}] [{bar}] {decimal_bytes}/{decimal_total_bytes} ({decimal_bytes_per_sec}, {eta})",
    )?
    .progress_chars("#>-");
    let pb = ProgressBar::new(estimated_download_bytes).with_style(progress_style);

    let depot_key_for_closure = decoded_depot_key;
    let retry_num = config.retry_num;
    let client_for_closure = &client;
    let cdn_url_suffix_list_for_closure = Arc::clone(&cdn_url_suffix_list);
    let cdn_url_list_for_closure = Arc::clone(&cdn_url_list);
    let cdn_health_for_closure = Arc::new(CdnHealth::new(cdn_url_list_for_closure.len()));
    let pb_for_closure = &pb;
    // Step 3: download and process all chunks
    stream::iter(all_chunks.into_iter().map(Ok::<ChunkInfo, Error>))
        .try_for_each_concurrent(cpu_num * 4, |chunk_info| {
            let depot_key_for_task = depot_key_for_closure.clone();
            let cdn_url_list_for_task = Arc::clone(&cdn_url_list_for_closure);
            let cdn_url_suffix_list_for_task = Arc::clone(&cdn_url_suffix_list_for_closure);
            let cdn_health_for_task = Arc::clone(&cdn_health_for_closure);
            async move {
                let data = chunk_info
                    .get_chunk(
                        cdn_url_list_for_task.as_ref(),
                        client_for_closure,
                        retry_num,
                        cdn_url_suffix_list_for_task.as_ref(),
                        cdn_health_for_task.as_ref(),
                    )
                    .await?;

                pb_for_closure.inc(data.len() as u64);

                let depot_key_for_spawn = depot_key_for_task;
                let original_size = chunk_info.original_size;

                let decrypted_data = spawn_blocking(move || -> Result<Vec<u8>, Error> {
                    let mut decrypt = Decrypt::new(data);
                    decrypt.set_key(depot_key_for_spawn);
                    let decrypted_data = decrypt.decrypt_chunk()?;
                    let data = decompress(decrypted_data)?;

                    if data.len() == original_size as usize {
                        Ok(data)
                    } else {
                        Err(Error::Message(format!(
                            "Size mismatch: expected {} got {}",
                            original_size,
                            data.len()
                        )))
                    }
                })
                .await??;

                chunk_info.write_chunk_into_file(decrypted_data).await?;
                Ok::<(), Error>(())
            }
        })
        .await?;

    Ok(())
}
