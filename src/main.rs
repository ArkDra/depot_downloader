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
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use liblzma::stream::{Action::Run, Filters, Stream};
use protobuf::Message;
use reqwest::{Client, Proxy};
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::{
    fs::{self, File},
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::AsyncWriteExt,
    task::spawn_blocking,
    time::{Duration, sleep},
};
type Error = Box<dyn std::error::Error>;
#[cfg(windows)]
const INVALID_CHARS: &[char] = &['/', ':', '*', '?', '"', '<', '>', '|'];
static NEXT_URL_INDEX: AtomicUsize = AtomicUsize::new(0);

const MAGIC_LZMA: [u8; 3] = [86, 90, 97]; // "VZa"
const MAGIC_ZSTD: [u8; 4] = [86, 83, 90, 97]; // "VSZa"
const MAGIC_ZIP: [u8; 4] = [80, 75, 3, 4]; // "PK\x03\x04"

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
    #[command(subcommand)]
    cdn: Option<CdnCommends>,
}
impl Args {
    pub fn get_args(&self) -> (&str, &str, &str, &Option<String>, u32, Option<Vec<(String, String)>>) {

        let cdn_pairs = match &self.cdn {
            Some(CdnCommends::Cdn { cdn_url, cdn_url_suffix }) => {
                if cdn_url.len() != cdn_url_suffix.len() {
                    panic!("The number of cdn_url and cdn_url_suffix must be the same");
                }
                Some(
                    cdn_url
                        .iter().cloned()
                        .zip(cdn_url_suffix.iter().cloned())
                        .collect(),
                )
            }
            None => None,
        };
        (
            &self.manifest_path,
            &self.depot_key,
            &self.output_path,
            &self.proxy_url,
            self.retry_num,
            cdn_pairs,
        )
    }
}

#[derive(Subcommand)]
enum CdnCommends { 
    Cdn {
       #[arg(short = 'u', long, required = true, num_args = 1.., value_delimiter = ',')]
        cdn_url: Vec<String>,
        #[arg(short = 's', long, required = true, num_args = 1.., value_delimiter = ',')]
        cdn_url_suffix: Vec<String>,
    }
}

#[derive(Clone)]
struct ChunkInfo {
    offset: u64,
    original_size: u32,
    depot_id: u32,
    file_path: PathBuf,
    content_sha: String,
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
        cdn_url_list: Vec<String>,
        client: &Client,
        retry_num: u32,
        cdn_url_suffix_list: Vec<String>,
    ) -> Vec<u8> {
        let url_list_len = cdn_url_list.len();
        let mut index = NEXT_URL_INDEX.fetch_add(1, Ordering::Relaxed) % url_list_len;
        let mut retry_count = 0;

        loop {
            let url = format!(
                "http://{}/depot/{}/chunk/{}{}",
                &cdn_url_list[index], self.depot_id, self.content_sha, &cdn_url_suffix_list[index]
            );
            match client.get(&url).send().await {
                Ok(res) => match res.bytes().await {
                    Ok(body_data) => {
                        if body_data.len() != 0 {
                            return body_data.to_vec();
                        }
                    }
                    Err(_) => {
                        // eprintln!("Failed to read response body: {}", e);
                    }
                },
                Err(_) => {
                    // eprintln!("Request error: {}", e);
                }
            }

            retry_count += 1;
            if retry_count < retry_num {
                sleep(Duration::from_millis(200)).await;
                index = (index + 1) % url_list_len;
            } else {
                eprintln!("Max retries reached. Aborting.");
                return vec![];
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
    pub fn new(manifest_path: &str) -> Self {
        let file = std::fs::File::open(manifest_path).unwrap();
        let mut bufreader = BufReader::new(file);
        let mut manifest_content = Vec::new();
        let _ = bufreader.read_to_end(&mut manifest_content);
        Manifest { manifest_content }
    }

    pub fn deserialize_manifest(
        &self,
    ) -> Result<(ContentManifestPayload, ContentManifestMetadata), Error> {
        let mut cursor = Cursor::new(&self.manifest_content);
        let mut payload_length = [0u8; 4];
        let _ = std::io::Cursor::seek(&mut cursor, SeekFrom::Start(4));
        let _ = cursor.read_exact(&mut payload_length);
        let payload_length = u32::from_le_bytes(payload_length);
        let mut payload = vec![0u8; payload_length as usize];
        let _ = cursor.read_exact(&mut payload);
        let _ = std::io::Cursor::seek(&mut cursor, SeekFrom::Current(4));
        let mut metadata_length = [0u8; 4];
        let _ = cursor.read_exact(&mut metadata_length);
        let metadata_length = u32::from_le_bytes(metadata_length);
        let mut metadata = vec![0u8; metadata_length as usize];
        let _ = cursor.read_exact(&mut metadata);
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
        let key = HEXLOWER.decode(&self.key)?;
        let mut block = GenericArray::from_slice(iv).to_owned();
        let mut cipher = ecb::Decryptor::<Aes256>::new_from_slice(&key)?;
        cipher.decrypt_block_mut(&mut block);
        let data = block.to_vec();
        Ok(data)
    }

    fn cbc_decrypt(&self, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let key = HEXLOWER.decode(&self.key)?;
        let cipher = cbc::Decryptor::<Aes256>::new_from_slices(&key, &self.iv)
            .map_err(|e| format!("Invalid key or IV: {:?}", e))?;
        let decrypted_data = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .map_err(|e| format!("Unpadding error: {:?}", e))?;
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

fn set_client(proxy_url: &Option<String>) -> Result<Client, Error> {
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
    let text = &response.text().await?;
    let json_data: Value = serde_json::from_str(&text)?;
    let servers = json_data["response"]["servers"]
        .as_array()
        .ok_or("servers not found")?;

    let mut url_list = Vec::new();
    for server in servers {
        if server["weighted_load"].as_i64() <= Some(130) {
            if let Some(host) = server["host"].as_str() {
                if host.contains("steamcontent.com") {
                    url_list.push(host.to_string());
                }
            }
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
    let depot_id_string = depot_id.to_string();
    let path = if output_path == "default" {
        let mut path_buf = std::env::current_dir()?;
        path_buf.push(depot_id_string);
        path_buf.push(file_name);
        path_buf
    } else {
        Path::new(output_path).join(depot_id_string).join(file_name)
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
        if let Some(parent_dir) = path.parent() {
            if !parent_dir.exists() {
                fs::create_dir_all(parent_dir)?;
            }
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
        let filter = filter.lzma1_properties(&compressed_data[7..12])?;
        Stream::new_raw_decoder(&filter)?.process_vec(raw_data, &mut decrypted_data, Run)?;

        if crc == crc32fast::hash(&decrypted_data) {
            return Ok(decrypted_data);
        } else {
            return Err("decompressed lzma data CRC mismatch".into());
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
            return Ok(decrypted_data);
        } else {
            return Err("decompressed zstd data CRC mismatch".into());
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
            return Ok(decrypted_data);
        } else {
            return Err("decompressed zip data CRC mismatch".into());
        }
    } else {
        Err("vz Unknown file format detected".into())
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let (manifest_path, depot_key, output_path, proxy_url, retry_num, cdn_pairs) =
        args.get_args();

    let manifest = Manifest::new(manifest_path);
    let (payload, metadata) = Manifest::deserialize_manifest(&manifest)?;

    let client = set_client(proxy_url)?;

    let (cdn_url_list, cdn_url_suffix_list): (Vec<String>, Vec<String>) = match cdn_pairs {
        Some(pairs) => pairs.into_iter().unzip(),
        None => {
            let urls = get_cdn_url_list(&client).await?;
            let urls_len = urls.len();
            (urls, vec!["".to_string(); urls_len])
        }
    };

    let cpu_num = num_cpus::get();

    for file in payload.mappings {
        if file.flags == 0 {
            let file_name = if metadata.filenames_encrypted {
                let depot_key_clone = depot_key.to_owned().into_bytes();
                let decoded_file_name = BASE64_MIME.decode(file.filename.as_bytes())?;
                let mut decrypt = Decrypt::new(decoded_file_name);
                decrypt.set_key(depot_key_clone);
                decrypt.decrypt_file_name()?
            } else {
                file.filename
            };

            let file_sha = HEXLOWER.encode(&file.sha_content);
            let (is_exist, path) = prepare_output_file(
                &file_name,
                file_sha,
                metadata.depot_id,
                output_path,
                file.size,
            )?;
            if is_exist {
                continue;
            }

            let pb = ProgressBar::new(file.size).with_style(ProgressStyle::with_template(
                "[{elapsed_precise}] [{msg}] [{bar}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
            )?
            .progress_chars("#>-"));
            pb.set_message(file_name);

            let depot_key_for_closure = depot_key;
            let client_for_closure = &client;
            let cdn_url_suffix_list_for_closure = &cdn_url_suffix_list;
            let cdn_url_list_for_closure = &cdn_url_list;
            let path_for_closure = &path;
            let pb_for_closure = &pb;

            stream::iter(file.chunks)
                .map(|chunk| async move {
                    let chunk_info = ChunkInfo::new(
                        chunk.offset,
                        chunk.cb_original,
                        metadata.depot_id,
                        path_for_closure.to_owned(),
                        HEXLOWER.encode(&chunk.sha),
                    );

                    let data = chunk_info
                        .get_chunk(
                            cdn_url_list_for_closure.to_owned(),
                            &client_for_closure,
                            retry_num,
                            cdn_url_suffix_list_for_closure.to_owned()
                        )
                        .await;

                    if data.len() == 0 {
                        return;
                    }

                    let depot_key_for_spawn = depot_key_for_closure.to_owned();

                    let decrypted_data = spawn_blocking(move || {
                        let mut decrypt = Decrypt::new(data);
                        decrypt.set_key(depot_key_for_spawn.into_bytes());
                        let decrypted_data =
                            decrypt.decrypt_chunk().expect("Failed to decrypt chunk");

                        let decompressed_data =
                            decompress(decrypted_data).expect("Failed to decompress chunk");

                        if decompressed_data.len() == chunk_info.original_size as usize {
                            Ok(decompressed_data.to_owned())
                        } else {
                            Err("size mismatch")
                        }
                    })
                    .await
                    .unwrap()
                    .expect("Failed to decrypt chunk");

                    chunk_info
                        .write_chunk_into_file(decrypted_data)
                        .await
                        .expect("Failed to write chunk into file");

                    pb_for_closure.inc(chunk.cb_original.into());
                })
                .buffer_unordered(cpu_num * 4)
                .collect::<Vec<_>>()
                .await;
        }
    }

    Ok(())
}
